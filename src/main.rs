#![cfg(unix)]

use std::{
    env, fs,
    os::fd::FromRawFd,
    path::{Path, PathBuf},
    rc::Rc,
};

use anyhow::{bail, Context, Result};
use futures::{select, FutureExt};
use http_body_util::Full;
use hyper::{
    body::Bytes, server::conn::http1, service::service_fn, Request, Response,
};
use smol_hyper::rt::{FuturesIo, SmolTimer};
// use no_panic::no_panic;
use clap::{Parser, Subcommand};
use smol::{
    io,
    net::unix::{SocketAddr, UnixListener, UnixStream},
    prelude::*,
    Async,
};
use tracing::{debug, error, event, info, span, warn, Level};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Prints out information about the server including version, config file
    /// location, etc.
    Info,
    /// Runs the server.
    Run {
        /// The path of the file which the configuration should be loaded
        /// from.
        config: String,
    },
    /// Stops the currently running server. If no server is running, does
    /// nothing.
    Stop,
    /// Instructs the server to reload the configuration file.
    Reload {
        /// The path of the file which the configuration should be loaded
        /// from.
        ///
        /// If none is given, the currently configured config file path is
        /// used.
        config: Option<PathBuf>,
    },
}

// #[no_panic]
fn unixlistener_name(u: &UnixListener) -> String {
    match u.local_addr() {
        Ok(addr) => format!(
            "{:?}",
            addr.as_pathname()
                .unwrap_or_else(|| Path::new("<anonymous socket>"))
        ),
        Err(_) => "<failed to get socket name>".to_string(),
    }
}

struct Config {
    socket_path: Option<String>,
    admin_socket_path: Option<String>,
}

// #[no_panic]
#[tracing::instrument]
fn parse_config(path: String) -> Result<Config> {
    info!("reading config from {}", path);
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("couldn't read config file '{}'", path))?;

    let mut result = Config {
        socket_path: None,
        admin_socket_path: None,
    };
    let mut lineno = 1;
    for line in contents.lines() {
        let line = match line.trim().split_once('#') {
            Some((lhs, _)) => lhs.trim(),
            None => "",
        };
        if line.is_empty() {
            lineno += 1;
            continue;
        }

        let (lhs, rhs) = match line.split_once('=') {
            Some((lhs, rhs)) => (lhs.trim(), rhs.trim()),
            None => bail!(
                "{}:{}: syntax error: expected '=', found end of line",
                path,
                lineno
            ),
        };

        match lhs {
            "socket path" => result.socket_path = Some(rhs.to_string()),
            "admin socket path" => {
                result.admin_socket_path = Some(rhs.to_string())
            }
            option => bail!(
                "{}: {}: error: unrecognized config option '{}'",
                path,
                lineno,
                option
            ),
        }
        lineno += 1;
    }

    Ok(result)
}

/// Returns a (work, admin) pair of unix sockets to listen on.
///
/// The work socket listens for incoming connections, and the admin socket
/// listens for administration commands.
#[tracing::instrument]
fn bind_sockets(
    admin_socket_path: &str,
) -> Result<(UnixListener, UnixListener)> {
    // We're using socket activation.
    if let Ok(num_fds) = env::var("LISTEN_FDS") {
        let num_fds = num_fds
            .parse::<u32>()
            .expect("LISTEN_FDS was not a valid u32");
        if num_fds < 2 {
            error!("expected LISTEN_FDS to be at least 2, got {}", num_fds);
        }

        // SAFETY: Typically a UNIX server supporting socket activation will
        // prepare a socket before the server is launched and set LISTEN_FDS to
        // the number of sockets which are ready. We only want 1, so we check
        // if LISTEN_FDS is at least 1 and then generate a UNIX listener from
        // the socket, which is set to 3. If LISTEN_FDS is set, this is more
        // likely than not a UNIX server supporting socket activation, so we
        // take advantage of that fact. This should be safe since socket
        // activation is something which needs to be manually enabled in the
        // configuration file.
        let listener =
            unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
        let work = UnixListener::from(
            Async::new(listener)
                .expect("couldn't configure listener for async use"),
        );

        // SAFETY: like the previous listener, but this is the next fd. We
        // already checked that num_fds >= 2.
        let listener =
            unsafe { std::os::unix::net::UnixListener::from_raw_fd(4) };
        let admin = UnixListener::from(
            Async::new(listener)
                .expect("couldn't configure listener for async use"),
        );

        return Ok((work, admin));
    }

    // We'll listen on stdin.

    // SAFETY: fd 0 is stdin.
    let stdin = unsafe { std::os::unix::net::UnixListener::from_raw_fd(0) };
    let work = UnixListener::from(
        Async::new(stdin).expect("couldn't configure listener for async use"),
    );

    let admin = UnixListener::bind(admin_socket_path).with_context(|| {
        format!("failed to open admin socket at {}", admin_socket_path)
    })?;
    Ok((work, admin))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config_path = match args.command {
        Commands::Stop => todo!("write the stop command"),
        Commands::Info => todo!("write the info command"),
        Commands::Reload { config: _ } => todo!("write the reload command"),
        Commands::Run { config } => config,
    };

    let subscriber = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("failed to set up logger")?;

    let mut config = parse_config(config_path)?;
    if let None = config.admin_socket_path {
        let ddsend_admin = env::var("DDSEND_ADMIN")
            .context("failed to read admin socket path from DDSEND_ADMIN")?;
        config.admin_socket_path = Some(ddsend_admin);
    }
    let config = Rc::new(config);

    let (work, admin) =
        bind_sockets(config.admin_socket_path.as_ref().unwrap())?;
    event!(
        Level::INFO,
        work = unixlistener_name(&work),
        admin = unixlistener_name(&admin),
        "listening"
    );

    loop {
        smol::block_on(async { listen(&work, &admin).await })
            .unwrap_or_else(|e| error!("{:?}", e));
    }
}

#[tracing::instrument]
async fn listen(work: &UnixListener, admin: &UnixListener) -> Result<()> {
    loop {
        select! {
            conn = work.accept().fuse() => {
                let conn = FuturesIo::new(conn?.0);
                smol::spawn(async move {
                    if let Err(e) = http1::Builder::new()
                    .serve_connection(conn, service_fn(serve))
                    .await {
                        error!("{:?}", e);
                    }
                }).detach()
            },
            conn = admin.accept().fuse() => {
                let conn = FuturesIo::new(conn?.0);
                smol::spawn(async move {
                    if let Err(e) = http1::Builder::new()
                    .serve_connection(conn, service_fn(serve_admin))
                    .await {
                        error!("{:?}", e);
                    }
                }).detach()
            },
        };
    }
}

#[tracing::instrument]
async fn serve(
    r: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>> {
    Ok(Response::new(Full::new(Bytes::from("Hello, World"))))
}

#[tracing::instrument]
async fn serve_admin(
    r: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>> {
    Ok(Response::new(Full::new(Bytes::from("Hello, World"))))
}
