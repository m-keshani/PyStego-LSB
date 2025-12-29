# PyStego-LSB
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A Raw Python Implementation of LSB Image Steganography with GUI. No external crypto libraries used.**

---

### Steganography Tool

This is a Python-based tool that allows you to hide a message within an image using the Least Significant Bit (LSB) method of steganography.  
The tool also provides a graphical user interface (GUI) built with Tkinter, making it easy to encrypt (hide) and decrypt (reveal) messages in images.

---

## Features 🎉

- **🔒 Encrypt (Hide) Message in Image:** Embed a secret message into an image.
- **🔓 Decrypt (Reveal) Message from Image:** Extract hidden messages from an image.

---

## Requirements ⚙️

Ensure you have the following:

- **Python 3.x**
- **Pillow** (PIL Fork)
- **Tkinter**

You can install the required dependencies using the following:

```bash
pip install pillow
```

---

## How to Run 🚀

1. Clone or download the repository to your local machine.

2. Ensure you have Python 3.x installed on your system.

3. Install the necessary dependencies:

```bash
pip install pillow
```

4. Run the script:

```bash
python stego_gui.py
```

5. The GUI will appear, allowing you to either encrypt (hide) or decrypt (reveal) messages in images.

---

## Usage 📖
**Encrypt (Hide) Message 🔒**

1. Click Select Base Image to choose an image where the message will be embedded.

2. Enter the message you want to hide in the "Enter Message" box.

3. Click Encrypt & Save As... to save the image with the hidden message.

**Decrypt (Reveal) Message 🔓**

1. Click Select Stego Image (PNG) to choose the image with the hidden message.

2. Click Decrypt Image to reveal the hidden message.

---

## Contributing 🤝

At the moment, I'm working on this project solo. However, if you'd like to contribute in the future, feel free to fork the repository, make your changes, and submit a pull request. Contributions are always welcome!

---

## License 📄

This project is licensed under the MIT License. See the LICENSE file for details.
 [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
