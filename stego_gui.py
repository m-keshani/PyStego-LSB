import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from PIL import Image
import os

# --- Core Steganography Logic ---
class StegoCore:
    def __init__(self):
        self.delimiter = "#####END#####"

    def _to_bin(self, data):
        if isinstance(data, str):
            return ''.join([format(ord(i), "08b") for i in data])
        raise TypeError("Input must be string.")

    def _bin_to_str(self, binary_data):
        all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]
        decoded_data = ""
        for byte in all_bytes:
            try:
                decoded_data += chr(int(byte, 2))
            except ValueError:
                continue # Skip invalid bytes
            if decoded_data.endswith(self.delimiter):
                return decoded_data[:-len(self.delimiter)]
        return decoded_data

    def embed_msg(self, img_path, msg, output_path):
        try:
            img = Image.open(img_path).convert('RGB')
            width, height = img.size
            max_bytes = width * height * 3 // 8

            full_msg = msg + self.delimiter
            bin_msg = self._to_bin(full_msg)
            data_len = len(bin_msg)

            if data_len > width * height * 3:
                raise ValueError(f"Message too long. Capacity: {max_bytes} bytes.")

            pixels = list(img.getdata())
            new_pixels = []
            idx = 0

            for r, g, b in pixels:
                if idx < data_len:
                    r = (r & 0xFE) | int(bin_msg[idx])
                    idx += 1
                if idx < data_len:
                    g = (g & 0xFE) | int(bin_msg[idx])
                    idx += 1
                if idx < data_len:
                    b = (b & 0xFE) | int(bin_msg[idx])
                    idx += 1
                new_pixels.append((r, g, b))

            new_img = Image.new(img.mode, img.size)
            new_img.putdata(new_pixels)
            
            # Force PNG for lossless storage
            if not output_path.lower().endswith('.png'):
                output_path += '.png'
            
            new_img.save(output_path)
            return True, output_path
        except Exception as e:
            return False, str(e)

    def extract_msg(self, img_path):
        try:
            img = Image.open(img_path).convert('RGB')
            pixels = list(img.getdata())
            bin_data = ""
            for r, g, b in pixels:
                bin_data += str(r & 1)
                bin_data += str(g & 1)
                bin_data += str(b & 1)
            
            return True, self._bin_to_str(bin_data)
        except Exception as e:
            return False, str(e)

# --- GUI Implementation ---
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LSB Steganography Tool")
        self.geometry("600x500")
        self.resizable(False, False)
        self.stego = StegoCore()
        self.enc_img_path = None
        self.dec_img_path = None

        self._init_ui()

    def _init_ui(self):
        # Using Notebook for tabs
        from tkinter import ttk
        tab_control = ttk.Notebook(self)
        self.tab_enc = ttk.Frame(tab_control)
        self.tab_dec = ttk.Frame(tab_control)
        tab_control.add(self.tab_enc, text='Encrypt (Hide)')
        tab_control.add(self.tab_dec, text='Decrypt (Reveal)')
        tab_control.pack(expand=1, fill="both")

        self._setup_enc_tab()
        self._setup_dec_tab()

    def _setup_enc_tab(self):
        frame = ttk.LabelFrame(self.tab_enc, text="Hide Message in Image", padding=20)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Image Selection
        btn_select = ttk.Button(frame, text="Select Base Image", command=self._select_enc_image)
        btn_select.pack(pady=(0, 5), anchor="w")
        self.lbl_enc_path = ttk.Label(frame, text="No image selected", wraplength=500, foreground="gray")
        self.lbl_enc_path.pack(pady=(0, 20), anchor="w")

        # Message Entry
        ttk.Label(frame, text="Enter Message:").pack(anchor="w")
        self.txt_msg = scrolledtext.ScrolledText(frame, height=8, width=60)
        self.txt_msg.pack(pady=(0, 20))

        # Action Button
        self.btn_run_enc = ttk.Button(frame, text="Encrypt & Save As...", command=self._run_encrypt, state="disabled")
        self.btn_run_enc.pack(anchor="center")

    def _setup_dec_tab(self):
        frame = ttk.LabelFrame(self.tab_dec, text="Reveal Message from Image", padding=20)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Image Selection
        btn_select = ttk.Button(frame, text="Select Stego Image (PNG)", command=self._select_dec_image)
        btn_select.pack(pady=(0, 5), anchor="w")
        self.lbl_dec_path = ttk.Label(frame, text="No image selected", wraplength=500, foreground="gray")
        self.lbl_dec_path.pack(pady=(0, 20), anchor="w")

        # Action Button
        self.btn_run_dec = ttk.Button(frame, text="Decrypt Image", command=self._run_decrypt, state="disabled")
        self.btn_run_dec.pack(pady=(0, 20), anchor="center")

        # Result Display
        ttk.Label(frame, text="Hidden Message:").pack(anchor="w")
        self.txt_result = scrolledtext.ScrolledText(frame, height=8, width=60, state="disabled")
        self.txt_result.pack()

    # --- Callbacks ---
    def _select_enc_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg *.jpeg *.png *.bmp")])
        if path:
            self.enc_img_path = path
            self.lbl_enc_path.config(text=path, foreground="black")
            self.btn_run_enc.config(state="normal")

    def _select_dec_image(self):
        path = filedialog.askopenfilename(filetypes=[("PNG Files", "*.png")])
        if path:
            self.dec_img_path = path
            self.lbl_dec_path.config(text=path, foreground="black")
            self.btn_run_dec.config(state="normal")

    def _run_encrypt(self):
        msg = self.txt_msg.get("1.0", tk.END).strip()
        if not msg:
            messagebox.showwarning("Warning", "Please enter a message.")
            return
        
        out_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if out_path:
            success, result = self.stego.embed_msg(self.enc_img_path, msg, out_path)
            if success:
                messagebox.showinfo("Success", f"Image saved to:\n{result}")
                self.txt_msg.delete("1.0", tk.END)
            else:
                messagebox.showerror("Error", result)

    def _run_decrypt(self):
        self.txt_result.config(state="normal")
        self.txt_result.delete("1.0", tk.END)
        
        success, result = self.stego.extract_msg(self.dec_img_path)
        if success:
            if not result:
                 result = "[No valid hidden message found or message is empty]"
            self.txt_result.insert(tk.INSERT, result)
        else:
            messagebox.showerror("Error", result)
        self.txt_result.config(state="disabled")

if __name__ == "__main__":
    app = App()
    app.mainloop()