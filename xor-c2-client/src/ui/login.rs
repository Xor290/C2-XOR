use crate::api::ApiClient;
use crate::state::C2Client;
use eframe::egui;

impl C2Client {
    pub fn render_login_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            let available_height = ui.available_height();

            ui.vertical_centered(|ui| {
                ui.add_space(available_height / 3.0);

                ui.heading("XOR C2 Client");
                ui.add_space(30.0);

                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(30, 30, 30))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(60, 60, 60)))
                    .inner_margin(20.0)
                    .show(ui, |ui| {
                        ui.set_width(400.0);

                        ui.label("Server URL:");
                        ui.text_edit_singleline(&mut self.server_url);
                        ui.add_space(10.0);

                        ui.label("Username:");
                        ui.text_edit_singleline(&mut self.username);
                        ui.add_space(10.0);

                        ui.label("Password:");
                        ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                        ui.add_space(20.0);

                        if !self.login_error.is_empty() {
                            ui.colored_label(egui::Color32::RED, &self.login_error);
                            ui.add_space(10.0);
                        }

                        let login_button = ui.add_sized([380.0, 40.0], egui::Button::new("Login"));

                        if login_button.clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            self.handle_login();
                        }
                    });
            });
        });
    }

    pub fn handle_login(&mut self) {
        self.loading = true;
        self.login_error.clear();

        let server_url = self.server_url.clone();
        let username = self.username.clone();
        let password = self.password.clone();
        let rt = self.rt.clone();

        match rt.block_on(ApiClient::login(&server_url, &username, &password)) {
            Ok(token) => {
                self.token = Some(token);
                self.is_authenticated = true;
                self.password.clear();
                self.refresh_data();
            }
            Err(e) => {
                self.login_error = e;
            }
        }

        self.loading = false;
    }

    pub fn handle_logout(&mut self) {
        if let Some(token) = &self.token {
            let _ = self.rt.block_on(ApiClient::logout(&self.server_url, token));
        }

        self.is_authenticated = false;
        self.token = None;
        self.agents.clear();
        self.selected_agent = None;
        self.results.clear();
    }
}
