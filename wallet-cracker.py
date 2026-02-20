#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EVM Wallet Cracker / Hunter — Búsqueda de fuerza bruta de frases semilla.
"""

import os
import threading
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

class EVMWalletCrackerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("EVM Wallet Cracker & Hunter")
        self.root.geometry("850x650")
        self.root.resizable(True, True)

        self.root.update_idletasks()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (w // 2)
        y = (self.root.winfo_screenheight() // 2) - (h // 2)
        self.root.geometry(f"+{x}+{y}")

        self.process = None
        self.is_running = False

        self._build_ui()

    def _build_ui(self):
        bg = "#1e1e2e"
        fg = "#cdd6f4"
        accent = "#f38ba8"       # rojo para herramienta ofensiva
        btn_bg = "#313244"
        btn_active = "#45475a"
        entry_bg = "#313244"
        font_main = ("Segoe UI", 10)
        font_title = ("Segoe UI", 16, "bold")
        font_mono = ("Consolas", 10)

        self.root.configure(bg=bg)

        tk.Label(
            self.root,
            text="🎯 EVM Wallet Cracker / Seed Hunter",
            font=font_title,
            bg=bg,
            fg=accent,
        ).pack(pady=(20, 5))

        tk.Label(
            self.root,
            text="Precaución: Matemáticamente esto es buscar una aguja en 5.4×10³⁹ pajares.",
            font=("Segoe UI", 9),
            bg=bg,
            fg="#a6adc8",
        ).pack(pady=(0, 15))

        # ── Target List File ──
        frame_target = tk.Frame(self.root, bg=bg)
        frame_target.pack(fill=tk.X, padx=20, pady=10)

        tk.Label(
            frame_target,
            text="Archivo de Objetivos (.txt):",
            font=font_main,
            bg=bg,
            fg=fg,
        ).pack(side=tk.LEFT)

        self.target_entry = tk.Entry(
            frame_target,
            font=font_mono,
            bg=entry_bg,
            fg=accent,
            insertbackground=fg,
            relief=tk.FLAT,
        )
        self.target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 10))

        self.btn_browse = tk.Button(
            frame_target,
            text="Examinar...",
            font=("Segoe UI", 9),
            bg=btn_bg,
            fg=fg,
            activebackground=btn_active,
            activeforeground=fg,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._browse_targets
        )
        self.btn_browse.pack(side=tk.RIGHT)

        # ── Partial Phrase ──
        frame_partial = tk.Frame(self.root, bg=bg)
        frame_partial.pack(fill=tk.X, padx=20, pady=5)

        tk.Label(
            frame_partial,
            text="Frase Parcial (Opcional, usa '?' para unknowns):",
            font=font_main,
            bg=bg,
            fg=fg,
        ).pack(side=tk.TOP, anchor=tk.W)

        self.partial_entry = tk.Entry(
            frame_partial,
            font=font_mono,
            bg=entry_bg,
            fg="#a6e3a1",
            insertbackground=fg,
            relief=tk.FLAT,
        )
        self.partial_entry.pack(fill=tk.X, expand=True, pady=(5, 0))
        self.partial_entry.insert(0, "")

        # ── Batch size (GPU) ──
        frame_threads = tk.Frame(self.root, bg=bg)
        frame_threads.pack(fill=tk.X, padx=20, pady=5)

        tk.Label(
            frame_threads,
            text="Paralelismo (hilos/batch):",
            font=font_main,
            bg=bg,
            fg=fg,
        ).pack(side=tk.LEFT)

        self.threads_entry = tk.Entry(
            frame_threads,
            font=font_main,
            bg=entry_bg,
            fg=fg,
            insertbackground=fg,
            relief=tk.FLAT,
            width=8,
            justify=tk.CENTER,
        )
        self.threads_entry.insert(0, "65536")
        self.threads_entry.pack(side=tk.RIGHT, padx=(10, 0))

        # ── Debug ──
        self.debug_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            frame_threads,
            text="Debug (logs detallados)",
            variable=self.debug_var,
            font=font_main,
            bg=bg,
            fg=fg,
            selectcolor=btn_bg,
            activebackground=bg,
            activeforeground=fg,
        ).pack(side=tk.LEFT, padx=(0, 20))

        # ── Botones ──
        frame_buttons = tk.Frame(self.root, bg=bg)
        frame_buttons.pack(pady=20)

        self.start_btn = tk.Button(
            frame_buttons,
            text="🔥 Iniciar Búsqueda Aleatoria",
            font=("Segoe UI", 11, "bold"),
            bg=accent,
            fg="#1e1e2e",
            activebackground="#f9e2af",
            activeforeground="#1e1e2e",
            relief=tk.FLAT,
            cursor="hand2",
            command=self._start_crack,
            padx=20,
            pady=8,
        )
        self.start_btn.pack(side=tk.LEFT, padx=10)

        self.stop_btn = tk.Button(
            frame_buttons,
            text="🛑 Detener",
            font=("Segoe UI", 11, "bold"),
            bg=btn_bg,
            fg=fg,
            activebackground=btn_active,
            activeforeground=fg,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._stop_crack,
            state=tk.DISABLED,
            padx=20,
            pady=8,
        )
        self.stop_btn.pack(side=tk.LEFT, padx=10)

        # ── Stats ──
        self.stats_var = tk.StringVar(value="Intentos: 0  |  Velocidad: 0 H/s")
        tk.Label(
            self.root,
            textvariable=self.stats_var,
            font=("Consolas", 12, "bold"),
            bg=bg,
            fg="#a6e3a1",
        ).pack(pady=5)

        # ── Consola de log ──
        self.log_area = scrolledtext.ScrolledText(
            self.root,
            font=font_mono,
            bg="#11111b",
            fg="#cdd6f4",
            insertbackground=fg,
            relief=tk.FLAT,
            height=12,
            state=tk.DISABLED,
        )
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=20, pady=(10, 20))

    def _log(self, msg: str):
        self.log_area.configure(state=tk.NORMAL)
        self.log_area.insert(tk.END, msg + "\n")
        self.log_area.see(tk.END)
        self.log_area.configure(state=tk.DISABLED)

    def _browse_targets(self):
        filepath = filedialog.askopenfilename(
            title="Seleccionar archivo de direcciones objetivo",
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")]
        )
        if filepath:
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, filepath)

    def _start_crack(self):
        target_file = self.target_entry.get().strip()
        batch_size = self.threads_entry.get().strip()
        partial_phrase = self.partial_entry.get().strip()

        if not target_file or not os.path.exists(target_file):
            messagebox.showerror("Error", "Debe seleccionar un archivo de objetivos válido.")
            return

        if not batch_size.isdigit() or int(batch_size) < 1:
            messagebox.showerror("Error", "Tamaño de batch inválido.")
            return

        if partial_phrase:
            words = partial_phrase.split()
            if len(words) > 24:
                messagebox.showerror("Error", f"La frase parcial tiene demasiadas palabras ({len(words)}). Máximo 24.")
                return
            
            # Autocompletado: si <= 12, completar a 12. Si > 12, completar a 24.
            target_len = 12 if len(words) <= 12 else 24
            while len(words) < target_len:
                words.append("?")
            partial_phrase = " ".join(words)

        script_dir = os.path.dirname(os.path.abspath(__file__))
        bip39_path = os.path.join(script_dir, "bip39.txt")
        hybrid_path = os.path.join(script_dir, "wallet-cracker")
        gpu_dir = os.path.join(script_dir, "wallet-cracking-gpu")
        gpu_path = os.path.join(gpu_dir, "wallet-cracker-gpu")
        if not os.path.exists(gpu_path):
            gpu_path = os.path.join(gpu_dir, "wallet-cracker")
        use_hybrid = os.path.exists(hybrid_path)
        exe_path = hybrid_path if use_hybrid else gpu_path

        if not os.path.exists(exe_path):
            messagebox.showerror("Falta Binario", "No se encontró wallet-cracker (híbrido) ni wallet-cracker-gpu. Compila: make wallet-cracker")
            return
        
        self.is_running = True
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.target_entry.configure(state=tk.DISABLED)
        self.btn_browse.configure(state=tk.DISABLED)
        self.threads_entry.configure(state=tk.DISABLED)
        self.partial_entry.configure(state=tk.DISABLED)

        self.log_area.configure(state=tk.NORMAL)
        self.log_area.delete("1.0", tk.END)
        self.log_area.configure(state=tk.DISABLED)

        self._log(f"[*] Cargando lista de objetivos desde: {target_file}")
        self._log(f"[*] Motor: {'Híbrido CPU+GPU' if use_hybrid else '100% GPU'} | {'Hilos' if use_hybrid else 'Batch'}: {batch_size}")
        if partial_phrase:
            self._log(f"[*] Modo: Frase Parcial ({partial_phrase})")
        else:
            self._log(f"[*] Modo: 100% Fuerza Bruta Aleatoria")
        self._log(f"[*] Enrutando batches CUDA...")

        target_abs = os.path.abspath(target_file)
        bip39_abs = os.path.abspath(bip39_path)
        exe_abs = os.path.abspath(exe_path)
        if use_hybrid:
            t = int(batch_size) if batch_size.isdigit() else (os.cpu_count() or 4)
            threads_val = str(min(max(t, 1), 64))
            cmd = [exe_abs, target_abs, bip39_abs, threads_val]
            if partial_phrase:
                cmd.append(partial_phrase)
        else:
            cmd = [exe_abs, target_abs, bip39_abs, batch_size]
            if self.debug_var.get():
                cmd.insert(1, "--debug")
            if partial_phrase:
                cmd.append(partial_phrase)

        def runner():
            try:
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    cwd=script_dir
                )

                # Leer stderr para progreso continuo
                for line in self.process.stderr:
                    if not self.is_running:
                        break
                    line = line.strip()
                    if line.startswith("Progreso:"):
                        self.root.after(0, self.stats_var.set, line)
                    else:
                        self.root.after(0, self._log, line)

                # Leer stdout por si hay un match
                match_text = ""
                matched_target = ""
                for line in self.process.stdout:
                    if "MATCH_FOUND:" in line:
                        parts = line.split("MATCH_FOUND:")[1].strip().split(":", 1)
                        if len(parts) == 2:
                            matched_target = parts[0]
                            match_text = parts[1]

                self.process.wait()

                if match_text:
                    self.root.after(0, self._handle_success, matched_target, match_text)
                else:
                    self.root.after(0, self._log, "[*] Proceso terminado.")

            except Exception as e:
                self.root.after(0, self._log, f"Error: {e}")
            finally:
                self.root.after(0, self._cleanup_ui)

        threading.Thread(target=runner, daemon=True).start()

    def _handle_success(self, target, phrase):
        self._log("\n\n" + "═" * 40)
        self._log("🎉 ¡¡MATCH ENCONTRADO!! 🎉")
        self._log(f"TARGET MATCHED: {target}")
        self._log(f"SEED PHRASE: {phrase}")
        self._log("═" * 40 + "\n")
        
        messagebox.showinfo(
            "¡BILLETERA CRACKEADA!",
            f"¡Hemos encontrado una semilla ganadora para uno de tus objetivos!\n\nTarget Encontrado:\n{target}\n\nSeed Phrase:\n{phrase}\n\n(Revisa el registro para copiar de manera segura)"
        )

    def _stop_crack(self):
        if self.process and self.process.poll() is None:
            self._log("\n[*] Deteniendo proceso...")
            self.process.terminate()
        self.is_running = False

    def _cleanup_ui(self):
        self.is_running = False
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.target_entry.configure(state=tk.NORMAL)
        self.btn_browse.configure(state=tk.NORMAL)
        self.threads_entry.configure(state=tk.NORMAL)
        self.partial_entry.configure(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = EVMWalletCrackerApp(root)
    root.mainloop()
