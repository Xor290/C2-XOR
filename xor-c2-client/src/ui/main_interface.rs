use crate::api::ApiClient;
use crate::state::C2Client;
use chrono::Local;
use eframe::egui;
use std::fs::File;
use std::io::Write;

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

                    egui::ComboBox::from_id_source("listener_type_select")
                        .selected_text(self.generate_listener_dialog.listener_type.as_str())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.generate_listener_dialog.listener_type,
                                "http".to_string(),
                                "HTTP",
                            );
                            ui.selectable_value(
                                &mut self.generate_listener_dialog.listener_type,
                                "https".to_string(),
                                "HTTPS",
                            );
                        });
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
                            if ui.button("X").clicked() {
                                to_remove = Some(i);
                            }
                        });
                    }

                    if let Some(index) = to_remove {
                        self.generate_listener_dialog.headers.remove(index);
                    }

                    if ui.button("+ Add Header").clicked() {
                        self.generate_listener_dialog
                            .headers
                            .push(("Header-Name".to_string(), "Header-Value".to_string()));
                    }
                });

                ui.add_space(10.0);

                if !self.generate_listener_dialog.status_message.is_empty() {
                    let color = if self.generate_listener_dialog.status_message.contains("OK") {
                        egui::Color32::GREEN
                    } else if self
                        .generate_listener_dialog
                        .status_message
                        .contains("Error")
                    {
                        egui::Color32::RED
                    } else {
                        egui::Color32::YELLOW
                    };
                    ui.colored_label(color, &self.generate_listener_dialog.status_message);
                    ui.add_space(5.0);
                }

                ui.separator();

                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        self.generate_listener_dialog.is_open = false;
                        self.generate_listener_dialog.status_message.clear();
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Generate").clicked() {
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
                    self.generate_listener_dialog.status_message = format!("OK: {}", message);

                    std::thread::sleep(std::time::Duration::from_millis(500));

                    self.refresh_data();
                }
                Err(error) => {
                    self.generate_listener_dialog.status_message = format!("Error: {}", error);
                }
            }
        }
    }

    pub fn render_generate_agent_dialog(&mut self, ctx: &egui::Context) {
        egui::Window::new("Generate Agent")
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
                    if ui.button("Cancel").clicked() {
                        self.generate_dialog.is_open = false;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let generate_btn = ui.add_enabled(
                            !self.generate_dialog.is_generating,
                            egui::Button::new(if self.generate_dialog.is_generating {
                                "Generating..."
                            } else {
                                "Generate"
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
                                    format!("Success! Agent saved to: {}", filename);

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

    pub fn render_main_interface(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("XOR C2 Client");
                ui.separator();

                ui.checkbox(&mut self.auto_refresh, "Auto-refresh");

                if ui.button("Refresh Now").clicked() {
                    self.refresh_data();
                }

                ui.separator();

                ui.menu_button("Generate Agent", |ui| {
                    if ui.button("Windows EXE").clicked() {
                        self.open_agent_generator("exe");
                        ui.close_menu();
                    }
                    if ui.button("Windows DLL").clicked() {
                        self.open_agent_generator("dll");
                        ui.close_menu();
                    }
                    if ui.button("Shellcode").clicked() {
                        self.open_agent_generator("shellcode");
                        ui.close_menu();
                    }
                });
                if ui.button("Generate Listener").clicked() {
                    self.generate_listener_dialog.is_open = true;
                    ui.close_menu();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Logout").clicked() {
                        self.handle_logout();
                    }
                    ui.label(format!("User: {}", self.username));
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
        ui.heading(format!("Active Agents ({})", self.agents.len()));
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
                        "[ON]"
                    } else {
                        "[WAIT]"
                    };

                    let button_text = format!(
                        "{} {}\nHost: {}\nUser: {}\nProcess: {}\nIP: {}\nPayload: {} | Listener: {}",
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
        ui.heading(if let Some(agent) = &self.selected_agent {
            format!(
                "Terminal - {} [{}]",
                agent.hostname.as_deref().unwrap_or("Unknown"),
                &agent.id[..8]
            )
        } else {
            "Terminal - Select an agent".to_string()
        });
        ui.separator();

        if let Some(agent) = &self.selected_agent {
            ui.horizontal(|ui| {
                ui.label(format!(
                    "User: {}",
                    agent.username.as_deref().unwrap_or("Unknown")
                ));
                ui.separator();
                ui.label(format!(
                    "Process: {}",
                    agent.process_name.as_deref().unwrap_or("Unknown")
                ));
                ui.separator();
                ui.label(format!("IP: {}", agent.ip.as_deref().unwrap_or("Unknown")));
            });
            ui.separator();
        }

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

                    let results_clone = self.results.clone(); // clone pour lecture dans closures
                    for i in 0..results_clone.len() {
                        if results_clone[i].is_command {
                            // index de la commande
                            let cmd_idx = i;

                            // clone des infos pour l'affichage
                            let collapse_symbol = if results_clone[cmd_idx].is_collapsed {
                                "▶"
                            } else {
                                "▼"
                            };
                            let content = results_clone[cmd_idx].content.clone();
                            let timestamp = results_clone[cmd_idx].timestamp.clone();

                            ui.horizontal(|ui| {
                                if ui.small_button(collapse_symbol).clicked() {
                                    // mutable borrow séparé hors de la closure
                                    let command = &mut self.results[cmd_idx];
                                    let new_state = !command.is_collapsed;
                                    command.is_collapsed = new_state;

                                    // appliquer aux résultats associés
                                    let mut j = cmd_idx + 1;
                                    while j < self.results.len() && !self.results[j].is_command {
                                        self.results[j].is_collapsed = new_state;
                                        j += 1;
                                    }
                                }

                                ui.colored_label(egui::Color32::GREEN, format!("$ {}", content));
                                ui.colored_label(
                                    egui::Color32::DARK_GRAY,
                                    format!("[{}]", timestamp),
                                );
                            });

                            // afficher résultats si pas collapsed
                            if !self.results[cmd_idx].is_collapsed {
                                let mut j = cmd_idx + 1;
                                while j < self.results.len() && !self.results[j].is_command {
                                    let r_content = self.results[j].content.clone();
                                    let r_timestamp = self.results[j].timestamp.clone();

                                    ui.horizontal(|ui| {
                                        ui.add_space(20.0);
                                        ui.vertical(|ui| {
                                            ui.colored_label(egui::Color32::LIGHT_GRAY, &r_content);
                                            if !r_timestamp.is_empty() {
                                                ui.colored_label(
                                                    egui::Color32::DARK_GRAY,
                                                    format!("  [{}]", r_timestamp),
                                                );
                                            }
                                        });
                                    });

                                    j += 1;
                                }
                            }
                        }
                    }
                });
        });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.label("$");
            let response = ui.add_enabled(
                self.selected_agent.is_some(),
                egui::TextEdit::multiline(&mut self.command_input)
                    .desired_rows(3) // hauteur initiale
                    .desired_width(ui.available_width() * 0.5) // largeur complète du panel
                    .lock_focus(true)
                    .hint_text("Enter command..."),
            );

            if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                self.handle_send_command();
                response.request_focus();
            }

            if ui
                .add_enabled(self.selected_agent.is_some(), egui::Button::new("Execute"))
                .clicked()
            {
                self.handle_send_command();
            }
        });

        if !self.command_error.is_empty() {
            ui.colored_label(egui::Color32::RED, &self.command_error);
        }
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

        // Marquer toutes les commandes existantes comme collapsed
        for result in &mut self.results {
            if result.is_command {
                result.is_collapsed = true;
            }
        }

        let command = self.command_input.clone();
        let agent_id = self.selected_agent.as_ref().unwrap().id.clone();
        let token = self.token.clone().unwrap();
        let server_url = self.server_url.clone();

        const MAX_HISTORY: usize = 5;

        if self.results.len() >= MAX_HISTORY * 2 {
            let keep_from = self.results.len().saturating_sub(MAX_HISTORY * 2);
            self.results = self.results.split_off(keep_from);
        }

        // Ajouter la nouvelle commande (elle reste expanded pour voir les résultats en temps réel)
        self.results.push(crate::models::CommandResult {
            timestamp: Local::now().format("%H:%M:%S").to_string(),
            is_command: true,
            content: command.clone(),
            result_id: None,
            is_file: false,
            is_collapsed: false, // La toute dernière commande reste visible
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
                Ok(mut new_results) => {
                    // Marquer tous les nouveaux résultats comme non-collapsed
                    for r in &mut new_results {
                        r.is_collapsed = false;
                    }

                    // Fusionner résultats existants + nouveaux résultats
                    // Conserver toutes les commandes précédentes et leurs résultats
                    let mut merged_results = self.results.clone();

                    // Ajouter seulement les nouvelles commandes/résultats qui n'existent pas déjà
                    for r in new_results {
                        let exists = merged_results
                            .iter()
                            .any(|old| old.timestamp == r.timestamp && old.content == r.content);
                        if !exists {
                            merged_results.push(r);
                        }
                    }

                    self.results = merged_results;

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
