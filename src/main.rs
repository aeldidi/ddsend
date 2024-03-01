#![cfg(unix)]

use std::{env, fs, os::fd::FromRawFd, rc::Rc};

use anyhow::{bail, Context, Result};
use futures::{select, FutureExt};
use smol::{io, net, prelude::*, Async, Unblock};
use tracing::{debug, error, info, span, warn, Level};

struct Config {
    admin_socket_path: String,
}

fn parse_config(path: String) -> Result<Config> {
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("couldn't read config file '{}'", path))?;

    let mut result = Config {
        admin_socket_path: path.clone(),
    };
    let mut lineno = 1;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') {
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
fn bind_sockets(
    admin_socket_path: &str,
) -> Result<(net::unix::UnixListener, net::unix::UnixListener)> {
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
        let work = net::unix::UnixListener::from(
            Async::new(listener)
                .expect("couldn't configure listener for async use"),
        );

        // SAFETY: like the previous listener, but this is the next fd. We
        // already checked that num_fds >= 2.
        let listener =
            unsafe { std::os::unix::net::UnixListener::from_raw_fd(4) };
        let admin = net::unix::UnixListener::from(
            Async::new(listener)
                .expect("couldn't configure listener for async use"),
        );

        return Ok((work, admin));
    }

    // We'll listen on stdin.

    // SAFETY: fd 0 is stdin.
    let stdin = unsafe { std::os::unix::net::UnixListener::from_raw_fd(0) };
    let work = net::unix::UnixListener::from(
        Async::new(stdin).expect("couldn't configure listener for async use"),
    );

    let admin = net::unix::UnixListener::bind(admin_socket_path).with_context(
        || format!("failed to open admin socket at {}", admin_socket_path),
    )?;
    Ok((work, admin))
}

fn main() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("failed to set up logger")?;

    let ddsend_admin = env::var("DDSEND_ADMIN")
        .context("failed to read config file location from DDSEND_ADMIN")?;
    let config = Rc::new(parse_config(ddsend_admin)?);
    let (work, config) = bind_sockets(&config.admin_socket_path)?;

    loop {
        if let Err(e) = smol::block_on(async { listen(&work, &config).await }) {
            error!("{:?}", e);
        }
    }
}

async fn listen(
    work: &net::unix::UnixListener,
    admin: &net::unix::UnixListener,
) -> Result<()> {
    loop {
        select! {
            conn = work.accept().fuse() => {
                let conn = conn?.0;
                serve(conn).await?
            },
            conn = admin.accept().fuse() => {
                let conn = conn?.0;
                serve_admin(conn).await?
            },
        };
    }
}

async fn serve(stream: net::unix::UnixStream) -> Result<()> {
    Ok(())
}

async fn serve_admin(stream: net::unix::UnixStream) -> Result<()> {
    Ok(())
}
