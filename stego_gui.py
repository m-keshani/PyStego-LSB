import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import threading
import os

# --- COLORS & CONFIG ---
# Trying to make it look like a cool cyberpunk terminal
DARK_BG = "#121212"
DARK_SEC = "#1e1e1e"
NEON_CYAN = "#00e5ff"  # For Encoding
NEON_PINK = "#ff007f"  # For Decoding
TEXT_COLOR = "#e0e0e0"
FONT_MAIN = ("Consolas", 10)
FONT_BOLD = ("Consolas", 11, "bold")

class LSBEngine:
    """
    Core LSB Logic.
    Works with Bytes to support UTF-8 (Persian, Emojis, etc.)
    """
    def __init__(self):
        self.stop_delimiter = "#####END#####"

    def encode(self, image_path, message, output_path):
        try:
            img = Image.open(image_path).convert('RGB')
            pixels = img.load()
            width, height = img.size

            # Prep message with delimiter
            full_msg = message + self.stop_delimiter
            msg_bytes = full_msg.encode('utf-8')
            
            # Convert to bits
            binary_msg = ''.join([format(b, "08b") for b in msg_bytes])
            msg_len = len(binary_msg)

            max_bits = width * height * 3
            if msg_len > max_bits:
                raise ValueError(f"Not enough pixels! Need {msg_len} bits, have {max_bits}.")

            data_idx = 0
            
            for y in range(height):
                for x in range(width):
                    pixel = list(pixels[x, y])
                    for n in range(3):
                        if data_idx < msg_len:
                            # Bitwise magic to set LSB
                            pixel[n] = pixel[n] & ~1 | int(binary_msg[data_idx])
                            data_idx += 1
                    pixels[x, y] = tuple(pixel)
                    if data_idx >= msg_len: break
                if data_idx >= msg_len: break
            
            img.save(output_path, "PNG")
            return True, "Success! Data hidden in the shadows."

        except Exception as e:
            return False, str(e)

    def decode(self, image_path):
        try:
            img = Image.open(image_path).convert('RGB')
            pixels = img.load()
            width, height = img.size
            
            delim_bytes = self.stop_delimiter.encode('utf-8')
            delim_len = len(delim_bytes)
            
            extracted = bytearray()
            curr_bits = ""
            
            for y in range(height):
                for x in range(width):
                    pixel = pixels[x, y]
                    for n in range(3):
                        curr_bits += str(pixel[n] & 1)
                        
                        if len(curr_bits) == 8:
                            byte_val = int(curr_bits, 2)
                            extracted.append(byte_val)
                            curr_bits = ""
                            
                            # Check for delimiter at the end
                            if len(extracted) >= delim_len:
                                if extracted[-delim_len:] == delim_bytes:
                                    # Found it!
                                    payload = extracted[:-delim_len]
                                    try:
                                        return True, payload.decode('utf-8')
                                    except:
                                        return False, "Decoded garbage (Encoding mismatch?)"
            
            return False, "No hidden message found."

        except Exception as e:
            return False, str(e)


class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PyStego // NEON EDITION")
        self.root.geometry("650x680")
        self.root.resizable(False, False)
        self.root.configure(bg=DARK_BG)
        
        # Customizing the ugly default ttk styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure Tabs to look Dark
        self.style.configure("TNotebook", background=DARK_BG, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=DARK_SEC, foreground="gray", padding=[10, 5], font=FONT_MAIN)
        self.style.map("TNotebook.Tab", background=[("selected", DARK_BG)], foreground=[("selected", NEON_CYAN)])
        
        # Frames
        self.style.configure("TFrame", background=DARK_BG)

        self.engine = LSBEngine()
        self.current_img_path = None

        self._init_ui()

    def _init_ui(self):
        # Header
        header = tk.Label(self.root, text="::: LSB STEGANOGRAPHY :::", bg=DARK_BG, fg=NEON_CYAN, font=("Consolas", 16, "bold"))
        header.pack(pady=15)

        self.tabs = ttk.Notebook(self.root)
        self.tab_enc = ttk.Frame(self.tabs)
        self.tab_dec = ttk.Frame(self.tabs)
        
        self.tabs.add(self.tab_enc, text='  ENCRYPT  ')
        self.tabs.add(self.tab_dec, text='  DECRYPT  ')
        self.tabs.pack(expand=1, fill="both", padx=15, pady=10)
        
        self._setup_encode_tab()
        self._setup_decode_tab()

    def _setup_encode_tab(self):
        frame = self.tab_enc
        
        # Image Area
        tk.Button(frame, text="[+] SELECT IMAGE", command=self.load_enc_image, 
                  bg=DARK_SEC, fg=NEON_CYAN, font=FONT_BOLD, relief="flat", borderwidth=0, activebackground=NEON_CYAN, activeforeground="black").pack(pady=15, ipadx=10, ipady=5)
        
        self.lbl_enc_preview = tk.Label(frame, text="NO SIGNAL", bg="black", fg="gray", width=50, height=10, relief="sunken", borderwidth=1)
        self.lbl_enc_preview.pack(pady=5)
        
        self.lbl_enc_path = tk.Label(frame, text="...", bg=DARK_BG, fg="gray", font=("Consolas", 8))
        self.lbl_enc_path.pack()

        # Text Input
        tk.Label(frame, text="> ENTER SECRET MESSAGE:", bg=DARK_BG, fg=TEXT_COLOR, font=FONT_BOLD).pack(pady=(20, 5), anchor="w", padx=45)
        
        self.txt_input = tk.Text(frame, height=5, width=50, bg=DARK_SEC, fg=NEON_CYAN, insertbackground=NEON_CYAN, font=("Consolas", 11), relief="flat", padx=5, pady=5)
        self.txt_input.pack(pady=5)
        
        # Action
        tk.Button(frame, text=">>> EXECUTE ENCRYPTION", command=self.run_encode, 
                  bg=NEON_CYAN, fg="black", font=("Consolas", 12, "bold"), relief="flat", activebackground="white").pack(pady=25, ipadx=20, ipady=5)

    def _setup_decode_tab(self):
        frame = self.tab_dec
        
        # Use Pink/Magenta for Decode theme
        tk.Button(frame, text="[+] LOAD ENCRYPTED PNG", command=self.load_dec_image, 
                  bg=DARK_SEC, fg=NEON_PINK, font=FONT_BOLD, relief="flat", activebackground=NEON_PINK, activeforeground="black").pack(pady=15, ipadx=10, ipady=5)
        
        self.lbl_dec_preview = tk.Label(frame, text="NO SIGNAL", bg="black", fg="gray", width=50, height=10, relief="sunken", borderwidth=1)
        self.lbl_dec_preview.pack(pady=5)

        self.lbl_dec_path = tk.Label(frame, text="...", bg=DARK_BG, fg="gray", font=("Consolas", 8))
        self.lbl_dec_path.pack()
        
        # Output Area
        tk.Label(frame, text="> DECODED OUTPUT:", bg=DARK_BG, fg=TEXT_COLOR, font=FONT_BOLD).pack(pady=(20, 5), anchor="w", padx=45)
        
        self.txt_output = tk.Text(frame, height=8, width=50, bg=DARK_SEC, fg=NEON_PINK, font=("Consolas", 11), relief="flat", state='disabled', padx=5, pady=5)
        self.txt_output.pack(pady=5)
        
        # Action
        tk.Button(frame, text=">>> EXTRACT DATA", command=self.run_decode, 
                  bg=NEON_PINK, fg="black", font=("Consolas", 12, "bold"), relief="flat", activebackground="white").pack(pady=25, ipadx=20, ipady=5)

    def load_enc_image(self):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg;*.jpeg;*.bmp")])
        if path:
            self.current_img_path = path
            self.lbl_enc_path.config(text=os.path.basename(path))
            self._show_preview(path, self.lbl_enc_preview)

    def load_dec_image(self):
        path = filedialog.askopenfilename(filetypes=[("Lossless", "*.png;*.bmp")])
        if path:
            self.current_img_path = path
            self.lbl_dec_path.config(text=os.path.basename(path))
            self._show_preview(path, self.lbl_dec_preview)

    def _show_preview(self, path, label_widget):
        try:
            img = Image.open(path)
            img.thumbnail((350, 180)) # Slightly bigger preview
            photo = ImageTk.PhotoImage(img)
            label_widget.config(image=photo, width=0, height=0)
            label_widget.image = photo 
        except Exception:
            pass

    def run_encode(self):
        if not self.current_img_path:
            messagebox.showwarning("ERR", "No Image Selected!")
            return
        
        msg = self.txt_input.get("1.0", tk.END).strip()
        if not msg:
            messagebox.showwarning("ERR", "Message is empty!")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".png", 
                                                 filetypes=[("PNG Image", "*.png")])
        if not save_path:
            return

        threading.Thread(target=self._process_encoding, args=(msg, save_path)).start()

    def _process_encoding(self, msg, save_path):
        success, result_msg = self.engine.encode(self.current_img_path, msg, save_path)
        if success:
            messagebox.showinfo("OK", result_msg)
        else:
            messagebox.showerror("FAIL", result_msg)

    def run_decode(self):
        if not self.current_img_path:
            messagebox.showwarning("ERR", "Select an image first!")
            return

        threading.Thread(target=self._process_decoding).start()

    def _process_decoding(self):
        success, result_msg = self.engine.decode(self.current_img_path)
        self.root.after(0, lambda: self._update_decode_output(success, result_msg))

    def _update_decode_output(self, success, text):
        self.txt_output.config(state='normal')
        self.txt_output.delete("1.0", tk.END)
        self.txt_output.insert("1.0", text)
        self.txt_output.config(state='disabled')
        
        if not success:
            messagebox.showerror("FAIL", text)

if __name__ == "__main__":
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()
