use binsign_core::{crypto, firmware};
use ed25519_dalek::{Signature, VerifyingKey};
use eframe::egui;
use rfd::FileDialog;
use std::path::{Path, PathBuf};

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "binsign",
        options,
        Box::new(|_cc| Box::new(BinsignApp::default())),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Generate,
    Sign,
    Verify,
}

struct BinsignApp {
    view: View,
    logs: Vec<String>,

    gen_dir: String,
    gen_password: String,
    gen_confirm: String,
    gen_overwrite: bool,

    sign_firmware: String,
    sign_key: String,
    sign_signature: String,
    sign_password: String,

    verify_firmware: String,
    verify_signature: String,
    verify_key: String,
}

impl Default for BinsignApp {
    fn default() -> Self {
        Self {
            view: View::Sign,
            logs: vec!["Ready.".to_string()],
            gen_dir: String::new(),
            gen_password: String::new(),
            gen_confirm: String::new(),
            gen_overwrite: false,
            sign_firmware: String::new(),
            sign_key: String::new(),
            sign_signature: String::new(),
            sign_password: String::new(),
            verify_firmware: String::new(),
            verify_signature: String::new(),
            verify_key: String::new(),
        }
    }
}

impl BinsignApp {
    fn log(&mut self, message: impl Into<String>) {
        self.logs.push(message.into());
    }

    fn pick_file(existing: Option<PathBuf>) -> Option<PathBuf> {
        let dialog = FileDialog::new();
        let dialog = if let Some(path) = existing {
            dialog.set_directory(path)
        } else {
            dialog
        };
        dialog.pick_file()
    }

    fn pick_folder(existing: Option<PathBuf>) -> Option<PathBuf> {
        let dialog = FileDialog::new();
        let dialog = if let Some(path) = existing {
            dialog.set_directory(path)
        } else {
            dialog
        };
        dialog.pick_folder()
    }

    fn default_signature_path(&self) -> PathBuf {
        let firmware_path = Path::new(&self.sign_firmware);
        if let Some(stem) = firmware_path.file_stem().and_then(|s| s.to_str()) {
            firmware_path
                .parent()
                .map(|parent| parent.join(format!("{}.sig", stem)))
                .unwrap_or_else(|| PathBuf::from(format!("{}.sig", stem)))
        } else {
            PathBuf::from("firmware.sig")
        }
    }

    fn default_key_path(&self) -> PathBuf {
        PathBuf::from("signing_key.bin")
    }

    fn default_public_key_path(&self) -> PathBuf {
        PathBuf::from("public_key.bin")
    }

    fn generate_keys(&mut self) {
        let dir = PathBuf::from(self.gen_dir.trim());
        if self.gen_password.is_empty() {
            self.log("Generation failed: password cannot be empty.");
            return;
        }
        if self.gen_password != self.gen_confirm {
            self.log("Generation failed: passwords do not match.");
            return;
        }

        match crypto::generate_key_pair_in_dir_with_password(
            &dir,
            &self.gen_password,
            self.gen_overwrite,
        ) {
            Ok(_) => self.log(format!("Generated key pair in {}", dir.display())),
            Err(e) => self.log(format!("Generation failed: {}", e)),
        }
    }

    fn sign(&mut self) {
        let firmware_path = PathBuf::from(self.sign_firmware.trim());
        if self.sign_password.is_empty() {
            self.log("Signing failed: password cannot be empty.");
            return;
        }

        let signing_key_path = if self.sign_key.trim().is_empty() {
            self.default_key_path()
        } else {
            PathBuf::from(self.sign_key.trim())
        };

        let signature_path = if self.sign_signature.trim().is_empty() {
            self.default_signature_path()
        } else {
            PathBuf::from(self.sign_signature.trim())
        };

        let firmware_data = match firmware::read_firmware_data(&firmware_path) {
            Ok(data) => data,
            Err(e) => {
                self.log(format!("Signing failed: {}", e));
                return;
            }
        };

        let signing_key = match crypto::load_encrypted_signing_key_with_password(
            &signing_key_path,
            &self.sign_password,
        ) {
            Ok(key) => key,
            Err(e) => {
                self.log(format!("Signing failed: {}", e));
                return;
            }
        };

        let signature: Signature = crypto::sign(&firmware_data, &signing_key);
        match std::fs::write(&signature_path, signature.to_bytes()) {
            Ok(_) => self.log(format!("Signature saved to {}", signature_path.display())),
            Err(e) => self.log(format!("Signing failed: {}", e)),
        }
    }

    fn verify(&mut self) {
        let firmware_path = PathBuf::from(self.verify_firmware.trim());
        let signature_path = if self.verify_signature.trim().is_empty() {
            PathBuf::from("firmware.sig")
        } else {
            PathBuf::from(self.verify_signature.trim())
        };
        let public_key_path = if self.verify_key.trim().is_empty() {
            self.default_public_key_path()
        } else {
            PathBuf::from(self.verify_key.trim())
        };

        let firmware_data = match firmware::read_firmware_data(&firmware_path) {
            Ok(data) => data,
            Err(e) => {
                self.log(format!("Verification failed: {}", e));
                return;
            }
        };

        let public_key_bytes = match std::fs::read(&public_key_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.log(format!("Verification failed: {}", e));
                return;
            }
        };

        let public_key_bytes: [u8; 32] = match public_key_bytes.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                self.log("Verification failed: invalid public key length (expected 32 bytes)");
                return;
            }
        };

        let verifying_key = match VerifyingKey::from_bytes(&public_key_bytes) {
            Ok(key) => key,
            Err(e) => {
                self.log(format!("Verification failed: {}", e));
                return;
            }
        };

        let signature_bytes = match std::fs::read(&signature_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.log(format!("Verification failed: {}", e));
                return;
            }
        };

        let signature_bytes: [u8; 64] = match signature_bytes.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                self.log("Verification failed: invalid signature length (expected 64 bytes)");
                return;
            }
        };

        let signature = Signature::from_bytes(&signature_bytes);

        match crypto::verify(&signature, &firmware_data, &verifying_key) {
            Ok(_) => self.log(format!(
                "Verification successful for {}",
                firmware_path.display()
            )),
            Err(e) => self.log(format!("Verification failed: {}", e)),
        }
    }
}

impl eframe::App for BinsignApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle drag-and-drop file drops
        if !ctx.input(|i| i.raw.dropped_files.is_empty()) {
            ctx.input(|i| {
                for file in &i.raw.dropped_files {
                    if let Some(path) = &file.path {
                        let path_str = path.display().to_string();
                        match self.view {
                            View::Generate => {
                                self.gen_dir = path_str;
                            }
                            View::Sign => {
                                if self.sign_firmware.is_empty() {
                                    self.sign_firmware = path_str;
                                    if self.sign_signature.trim().is_empty() {
                                        self.sign_signature =
                                            self.default_signature_path().display().to_string();
                                    }
                                } else if self.sign_key.is_empty() {
                                    self.sign_key = path_str;
                                }
                            }
                            View::Verify => {
                                if self.verify_firmware.is_empty() {
                                    self.verify_firmware = path_str;
                                } else if self.verify_signature.is_empty() {
                                    self.verify_signature = path_str;
                                } else if self.verify_key.is_empty() {
                                    self.verify_key = path_str;
                                }
                            }
                        }
                    }
                }
            });
        }

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("binsign");
                ui.separator();
                ui.selectable_value(&mut self.view, View::Generate, "Generate Keys");
                ui.selectable_value(&mut self.view, View::Sign, "Sign");
                ui.selectable_value(&mut self.view, View::Verify, "Verify");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.spacing_mut().item_spacing = egui::vec2(12.0, 10.0);

            // Drag-and-drop hint
            if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
                ui.colored_label(egui::Color32::LIGHT_BLUE, "📁 Drop files here");
            }

            match self.view {
                View::Generate => {
                    ui.heading("Generate Key Pair");
                    ui.horizontal(|ui| {
                        ui.label("Output folder");
                        ui.text_edit_singleline(&mut self.gen_dir);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = Self::pick_folder(None) {
                                self.gen_dir = path.display().to_string();
                            }
                        }
                    });
                    ui.checkbox(&mut self.gen_overwrite, "Overwrite existing key files");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.gen_password)
                            .password(true)
                            .hint_text("Password"),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.gen_confirm)
                            .password(true)
                            .hint_text("Confirm password"),
                    );
                    if ui.button("Generate").clicked() {
                        self.generate_keys();
                    }
                }
                View::Sign => {
                    ui.heading("Sign Firmware");
                    ui.horizontal(|ui| {
                        ui.label("Firmware");
                        ui.text_edit_singleline(&mut self.sign_firmware);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = Self::pick_file(None) {
                                self.sign_firmware = path.display().to_string();
                                if self.sign_signature.trim().is_empty() {
                                    self.sign_signature =
                                        self.default_signature_path().display().to_string();
                                }
                            }
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Signing key");
                        ui.text_edit_singleline(&mut self.sign_key);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = Self::pick_file(None) {
                                self.sign_key = path.display().to_string();
                            }
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Signature output");
                        ui.text_edit_singleline(&mut self.sign_signature);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = Self::pick_file(None) {
                                self.sign_signature = path.display().to_string();
                            }
                        }
                    });
                    ui.add(
                        egui::TextEdit::singleline(&mut self.sign_password)
                            .password(true)
                            .hint_text("Signing key password"),
                    );
                    if ui.button("Sign").clicked() {
                        self.sign();
                    }
                }
                View::Verify => {
                    ui.heading("Verify Firmware");
                    ui.horizontal(|ui| {
                        ui.label("Firmware");
                        ui.text_edit_singleline(&mut self.verify_firmware);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = Self::pick_file(None) {
                                self.verify_firmware = path.display().to_string();
                            }
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Signature");
                        ui.text_edit_singleline(&mut self.verify_signature);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = Self::pick_file(None) {
                                self.verify_signature = path.display().to_string();
                            }
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Public key");
                        ui.text_edit_singleline(&mut self.verify_key);
                        if ui.button("Browse").clicked() {
                            if let Some(path) = Self::pick_file(None) {
                                self.verify_key = path.display().to_string();
                            }
                        }
                    });
                    if ui.button("Verify").clicked() {
                        self.verify();
                    }
                }
            }

            ui.separator();
            ui.heading("Log");
            egui::ScrollArea::vertical()
                .max_height(220.0)
                .show(ui, |ui| {
                    for line in &self.logs {
                        ui.label(line);
                    }
                });
        });
    }
}
