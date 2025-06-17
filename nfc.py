import tkinter as tk
from tkinter import messagebox
from smartcard.System import readers
from smartcard.util import toHexString

class NFCReaderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NFC Card Reader")
        self.root.geometry("400x250")
        self.root.resizable(False, False)

        self.reader_label = tk.Label(root, text="Reader: Not connected", font=("Arial", 12))
        self.reader_label.pack(pady=10)

        self.uid_label = tk.Label(root, text="Card UID: -", font=("Arial", 14, "bold"), fg="blue")
        self.uid_label.pack(pady=20)

        self.scan_button = tk.Button(root, text="Scan Card", font=("Arial", 12), command=self.scan_card)
        self.scan_button.pack(pady=10)

        self.status_label = tk.Label(root, text="Status: Ready", font=("Arial", 10), fg="green")
        self.status_label.pack(pady=10)

        self.pcsc_readers = []
        self.connection = None
        self.detect_reader()

    def detect_reader(self):
        try:
            self.pcsc_readers = readers()
            if not self.pcsc_readers:
                self.reader_label.config(text="Reader: Not found", fg="red")
                self.status_label.config(text="Status: No smart card reader found", fg="red")
                self.scan_button.config(state=tk.DISABLED)
            else:
                self.reader_label.config(text=f"Reader: {self.pcsc_readers[0]}", fg="black")
                self.status_label.config(text="Status: Ready", fg="green")
                self.scan_button.config(state=tk.NORMAL)
        except Exception as e:
            self.reader_label.config(text="Reader: Error", fg="red")
            self.status_label.config(text=f"Status: {e}", fg="red")
            self.scan_button.config(state=tk.DISABLED)

    def scan_card(self):
        self.uid_label.config(text="Card UID: -", fg="blue")
        self.status_label.config(text="Status: Scanning...", fg="orange")
        self.root.update()
        if not self.pcsc_readers:
            self.status_label.config(text="Status: No reader found", fg="red")
            return
        try:
            connection = self.pcsc_readers[0].createConnection()
            connection.connect()
            GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
            data, sw1, sw2 = connection.transmit(GET_UID)
            if (sw1, sw2) == (0x90, 0x00):
                uid = toHexString(data)
                self.uid_label.config(text=f"Card UID: {uid}", fg="blue")
                self.status_label.config(text="Status: Card read successfully", fg="green")
            else:
                self.uid_label.config(text="Card UID: -", fg="red")
                self.status_label.config(text=f"Status: Command failed (SW1={sw1:02X} SW2={sw2:02X})", fg="red")
            connection.disconnect()
        except Exception as e:
            self.uid_label.config(text="Card UID: -", fg="red")
            self.status_label.config(text=f"Status: {e}", fg="red")

if __name__ == "__main__":
    root = tk.Tk()
    app = NFCReaderApp(root)
    root.mainloop()
