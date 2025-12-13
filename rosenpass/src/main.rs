use anyhow::Result;
use log::error;
use rosenpass::{cli::Cli, sodium::sodium_init};
use std::process::exit;

#[cfg(windows)]
use rosenpass::wireguard;

pub fn main() {
    env_logger::init();

    // Run the actual program on a thread with a larger stack to avoid
    // stack overflow when liboqs (classic McEliece) allocates large
    // data on the stack.
    let result: Result<()> = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024) // 16 MiB
        .spawn(|| main_inner())
        .expect("failed to spawn main thread")
        .join()
        .expect("main thread panicked");

    // On Windows, always attempt to tidy up the WireGuard state.
    #[cfg(windows)]
    {
        wireguard::shutdown_all();
    }

    if let Err(e) = result {
        error!("{e}");
        exit(1);
    }
}

/// Inner main logic run on the larger-stack thread.
fn main_inner() -> Result<()> {
    sodium_init().and_then(|()| Cli::run())
}
