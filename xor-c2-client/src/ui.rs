mod login;
mod main_interface;

use crate::state::C2Client;
use eframe::egui;

impl eframe::App for C2Client {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.is_authenticated && self.auto_refresh {
            if self.last_refresh.elapsed().as_secs() >= 3 {
                self.refresh_data();
            }
        }

        if !self.is_authenticated {
            self.render_login_screen(ctx);
        } else {
            self.render_main_interface(ctx);
        }

        if self.generate_dialog.is_open {
            self.render_generate_agent_dialog(ctx);
        }
        if self.generate_listener_dialog.is_open {
            self.render_generate_listener(ctx);
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}
