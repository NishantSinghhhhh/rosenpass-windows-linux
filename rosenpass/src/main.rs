use log::error;
use rosenpass::{cli::Cli, sodium::sodium_init};
use std::process::exit;

#[cfg(windows)]
use rosenpass::wireguard;

pub fn main() {
    env_logger::init();

    let result = sodium_init().and_then(|()| Cli::run());

    #[cfg(windows)]
    {
        wireguard::shutdown_all();
    }

    if let Err(e) = result {
        error!("{e}");
        exit(1);
    }
}
