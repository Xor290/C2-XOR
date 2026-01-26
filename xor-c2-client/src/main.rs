mod api;
mod models;
mod state;
mod ui;
use eframe::egui;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 900.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("XOR C2 Client"),
        ..Default::default()
    };

    eframe::run_native(
        "XOR C2 Client",
        options,
        Box::new(|_cc| Box::new(state::C2Client::default())),
    )
}
