import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import threading
import os

class LSBEngine:
    """
    Handles the core logic for LSB (Least Significant Bit) steganography.
    Supports UTF-8 encoding for multilingual messages.
    """
    def __init__(self):
        # Unique sequence to mark the end of the message
        self.stop_delimiter = "#####END#####"

    def _str_to_bin(self, data_str):
        # Convert string to binary based on UTF-8 code points
        return ''.join([format(ord(char), "08b") for char in data_str])

    def encode(self, image_path, message, output_path):
        try:
            # We convert to RGB to ensure 3 channels (ignoring Alpha for LSB simplicity)
            img = Image.open(image_path).convert('RGB')
            pixels = img.load()
            width, height = img.size

            # Append delimiter to know where to stop decoding later
            full_message = message + self.stop_delimiter
            binary_msg = self._str_to_bin(full_message)
            msg_len = len(binary_msg)

            # Capacity check: each pixel holds 3 bits (R, G, B)
            max_bytes = (width * height * 3) // 8
            if msg_len > width * height * 3:
                raise ValueError(f"Message too large for this image. Max chars: {max_bytes}")

            data_idx = 0
            
            # Iterate through pixels to hide data
            for y in range(height):
                for x in range(width):
                    pixel = list(pixels[x, y])
                    
                    # Modify R, G, B values
                    for n in range(3):
                        if data_idx < msg_len:
                            # Bitwise Operation:
                            # 1. & ~1 : Clears the LSB (sets it to 0)
                            # 2. | int(...) : Sets LSB to the message bit
                            pixel[n] = pixel[n] & ~1 | int(binary_msg[data_idx])
                            data_idx += 1
                    
                    pixels[x, y] = tuple(pixel)
                    if data_idx >= msg_len:
                        break
                if data_idx >= msg_len:
                    break
            
            # Must save as PNG to prevent compression artifacts destroying the LSBs
            img.save(output_path, "PNG")
            return True, "Encryption successful! Image saved."

        except Exception as e:
            return False, f"Error during encoding: {str(e)}"

    def decode(self, image_path):
        try:
            img = Image.open(image_path).convert('RGB')
            pixels = img.load()
            width, height = img.size
            
            binary_data = []
            
            # Extract LSBs from the image
            for y in range(height):
                for x in range(width):
                    pixel = pixels[x, y]
                    for n in range(3):
                        binary_data.append(str(pixel[n] & 1))

            # Reconstruct the string
            # This approach is simple but might be memory intensive for huge 4k images.
            # Good enough for a semester project.
            binary_str = "".join(binary_data)
            
            # Split into 8-bit chunks (bytes)
            bytes_list = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
            
            decoded_msg = ""
            for byte in bytes_list:
                try:
                    char_code = int(byte, 2)
                    decoded_msg += chr(char_code)
                    
                    # Check for stop delimiter
                    if decoded_msg.endswith(self.stop_delimiter):
                        clean_msg = decoded_msg[:-len(self.stop_delimiter)]
                        return True, clean_msg
                except:
                    # If we hit garbage data or invalid chars, just continue
                    continue
            
            return False, "No hidden message found (Delimiter missing)."

        except Exception as e:
            return False, f"Error during decoding: {str(e)}"


class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PyStego LSB Tool")
        self.root.geometry("600x620")
        self.root.resizable(False, False)
        
        # Using 'clam' theme for a cleaner look on Linux/Windows
        style = ttk.Style()
        style.theme_use('clam')
        
        self.engine = LSBEngine()
        self.current_img_path = None

        self._init_ui()

    def _init_ui(self):
        # Notebook for tabbed interface
        self.tabs = ttk.Notebook(self.root)
        self.tab_enc = ttk.Frame(self.tabs)
        self.tab_dec = ttk.Frame(self.tabs)
        
        self.tabs.add(self.tab_enc, text='  Encrypt Message  ')
        self.tabs.add(self.tab_dec, text='  Decrypt Message  ')
        self.tabs.pack(expand=1, fill="both", padx=10, pady=10)
        
        self._setup_encode_tab()
        self._setup_decode_tab()

    def _setup_encode_tab(self):
        frame = self.tab_enc
        
        # Image Selection Section
        btn_frame = tk.Frame(frame)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Select Source Image", command=self.load_enc_image, 
                  bg="#007ACC", fg="white", padx=10).pack()
        
        self.lbl_enc_preview = tk.Label(frame, text="No Image Selected", bg="#E0E0E0", width=50, height=10)
        self.lbl_enc_preview.pack(pady=5)
        
        self.lbl_enc_path = tk.Label(frame, text="...", fg="gray", font=("Consolas", 8))
        self.lbl_enc_path.pack()

        # Text Input
        tk.Label(frame, text="Secret Message (Supports Unicode/Persian):", font=("Segoe UI", 10, "bold")).pack(pady=(15, 5))
        self.txt_input = tk.Text(frame, height=6, width=55, font=("Segoe UI", 10))
        self.txt_input.pack(pady=5)
        
        # Action Button
        tk.Button(frame, text="Encrypt & Save", command=self.run_encode, 
                  bg="#28A745", fg="white", font=("Segoe UI", 11, "bold"), padx=15).pack(pady=20)

    def _setup_decode_tab(self):
        frame = self.tab_dec
        
        # Image Selection Section
        tk.Button(frame, text="Select Encrypted Image", command=self.load_dec_image, 
                  bg="#6f42c1", fg="white", padx=10).pack(pady=10)
        
        self.lbl_dec_preview = tk.Label(frame, text="No Image Selected", bg="#E0E0E0", width=50, height=10)
        self.lbl_dec_preview.pack(pady=5)

        self.lbl_dec_path = tk.Label(frame, text="...", fg="gray", font=("Consolas", 8))
        self.lbl_dec_path.pack()
        
        # Output Area
        tk.Label(frame, text="Decoded Message:", font=("Segoe UI", 10, "bold")).pack(pady=(20, 5))
        self.txt_output = tk.Text(frame, height=8, width=55, font=("Segoe UI", 10), state='disabled')
        self.txt_output.pack(pady=5)
        
        # Action Button
        tk.Button(frame, text="Extract Message", command=self.run_decode, 
                  bg="#fd7e14", fg="white", font=("Segoe UI", 11, "bold"), padx=15).pack(pady=20)

    def load_enc_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if path:
            self.current_img_path = path
            self.lbl_enc_path.config(text=os.path.basename(path))
            self._show_preview(path, self.lbl_enc_preview)

    def load_dec_image(self):
        # We prefer PNG/BMP for decoding as they are lossless
        path = filedialog.askopenfilename(filetypes=[("Lossless Images", "*.png;*.bmp")])
        if path:
            self.current_img_path = path
            self.lbl_dec_path.config(text=os.path.basename(path))
            self._show_preview(path, self.lbl_dec_preview)

    def _show_preview(self, path, label_widget):
        try:
            img = Image.open(path)
            # Resize for thumbnail preview
            img.thumbnail((300, 150))
            photo = ImageTk.PhotoImage(img)
            label_widget.config(image=photo, width=0, height=0)
            label_widget.image = photo # Keep reference to avoid GC
        except Exception as e:
            print(f"Preview error: {e}")

    def run_encode(self):
        if not self.current_img_path:
            messagebox.showwarning("Warning", "Please select an image first.")
            return
        
        msg = self.txt_input.get("1.0", tk.END).strip()
        if not msg:
            messagebox.showwarning("Warning", "Message is empty.")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".png", 
                                                 filetypes=[("PNG Image", "*.png")])
        if not save_path:
            return

        # Running in a separate thread to keep UI responsive during processing
        threading.Thread(target=self._process_encoding, args=(msg, save_path)).start()

    def _process_encoding(self, msg, save_path):
        success, result_msg = self.engine.encode(self.current_img_path, msg, save_path)
        if success:
            messagebox.showinfo("Success", result_msg)
        else:
            messagebox.showerror("Error", result_msg)

    def run_decode(self):
        if not self.current_img_path:
            messagebox.showwarning("Warning", "Please select an image first.")
            return

        threading.Thread(target=self._process_decoding).start()

    def _process_decoding(self):
        success, result_msg = self.engine.decode(self.current_img_path)
        # Tkinter isn't thread-safe, so we schedule UI updates on the main loop
        self.root.after(0, lambda: self._update_decode_output(success, result_msg))

    def _update_decode_output(self, success, text):
        self.txt_output.config(state='normal')
        self.txt_output.delete("1.0", tk.END)
        self.txt_output.insert("1.0", text)
        self.txt_output.config(state='disabled')
        
        if not success:
            messagebox.showerror("Extraction Failed", text)

if __name__ == "__main__":
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()
