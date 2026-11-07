#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if otium_flow::protocol::updater::run_helper_if_requested().map_err(std::io::Error::other)? {
        return Ok(());
    }
    otium_flow::app::run(std::env::args().any(|a| a == "--mobile"))
}
