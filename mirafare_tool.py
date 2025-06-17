import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QComboBox, QLineEdit, QPushButton, QGridLayout, QTableWidget, QTableWidgetItem, QGroupBox, QVBoxLayout, QHBoxLayout, QSpinBox
)
from PyQt5.QtCore import Qt
from smartcard.System import readers

class MifareToolUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mifare Classic Tool by AiPulse")
        self.setGeometry(100, 100, 800, 500)
        self.selected_reader = None
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()

        # --- Device Info Line ---
        device_group = QGroupBox()
        device_layout = QHBoxLayout()
        device_layout.addWidget(QLabel("Show Readers:"))
        self.reader_combo = QComboBox()
        self.reader_combo.setFixedWidth(300)
        self.reader_combo.setStyleSheet("padding-left: 8px; margin-left: 4px;")
        device_layout.addWidget(self.reader_combo, stretch=1)

        # Centered status label with fixed width
        self.status_label = QLabel("Status: Device ready")
        self.status_label.setStyleSheet("color: orange; font-weight: bold;")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setFixedWidth(300)  # Reserve enough space for all messages
        device_layout.addStretch(1)
        device_layout.addWidget(self.status_label, stretch=0)
        device_layout.addStretch(1)

        self.connect_btn = QPushButton("Connect")
        device_layout.addWidget(self.connect_btn, stretch=0)

        device_group.setLayout(device_layout)
        main_layout.addWidget(device_group)

        # --- Card Info Line ---
        card_group = QGroupBox()
        card_layout = QHBoxLayout()
        card_layout.addWidget(QLabel("RFID (UID):"))
        self.uid_display = QLineEdit()
        self.uid_display.setReadOnly(True)
        self.uid_display.setStyleSheet("padding-left: 8px;")
        card_layout.addWidget(self.uid_display)
        card_layout.addWidget(QLabel("Card Type:"))
        self.card_type_display = QLineEdit("Mifare Classic 1K")
        self.card_type_display.setReadOnly(True)
        self.card_type_display.setStyleSheet("padding-left: 8px;")
        card_layout.addWidget(self.card_type_display)
        self.scan_btn = QPushButton("Scan Card")
        card_layout.addWidget(self.scan_btn)
        card_group.setLayout(card_layout)
        main_layout.addWidget(card_group)

        self.connect_btn.clicked.connect(self.connect_reader)
        self.scan_btn.clicked.connect(self.scan_card)
        self.refresh_readers()
        # Set initial status
        self.set_status_ready()


        # --- Sector/Block Selection ---
        sector_group = QGroupBox("Mifare 1K")
        sector_layout = QGridLayout()

        # Sector selection
        sector_layout.addWidget(QLabel("Sector:"), 0, 0)
        self.sector_spin = QSpinBox()
        self.sector_spin.setRange(0, 15)
        self.sector_spin.setFixedWidth(60)
        sector_layout.addWidget(self.sector_spin, 0, 1)

        # Block selection
        sector_layout.addWidget(QLabel("Block:"), 0, 2)
        self.block_spin = QSpinBox()
        self.block_spin.setRange(0, 3)
        self.block_spin.setFixedWidth(60)
        sector_layout.addWidget(self.block_spin, 0, 3)

        # Current selection label
        self.selection_label = QLabel()
        self.selection_label.setStyleSheet("font-weight: bold; margin-left: 10px;")
        sector_layout.addWidget(self.selection_label, 0, 4, 1, 2)

        # Update label on spin change
        self.sector_spin.valueChanged.connect(self.update_selection_label)
        self.block_spin.valueChanged.connect(self.update_selection_label)
        self.update_selection_label()

        # Key A
        sector_layout.addWidget(QLabel("Key A:"), 1, 0)
        self.key_a_input = QLineEdit("FF FF FF FF FF FF")
        sector_layout.addWidget(self.key_a_input, 1, 1)
        self.auth_a_btn = QPushButton("Authenticate (A)")
        sector_layout.addWidget(self.auth_a_btn, 1, 2)
        self.change_a_btn = QPushButton("Change")
        sector_layout.addWidget(self.change_a_btn, 1, 3)

        # Key B
        sector_layout.addWidget(QLabel("Key B:"), 2, 0)
        self.key_b_input = QLineEdit("FF FF FF FF FF FF")
        sector_layout.addWidget(self.key_b_input, 2, 1)
        self.auth_b_btn = QPushButton("Authenticate (B)")
        sector_layout.addWidget(self.auth_b_btn, 2, 2)
        self.change_b_btn = QPushButton("Change")
        sector_layout.addWidget(self.change_b_btn, 2, 3)

        # Connect buttons
        self.auth_a_btn.clicked.connect(self.authenticate_a)
        self.auth_b_btn.clicked.connect(self.authenticate_b)
        self.change_a_btn.clicked.connect(lambda: self.key_a_input.setFocus())
        self.change_b_btn.clicked.connect(lambda: self.key_b_input.setFocus())

        sector_group.setLayout(sector_layout)
        main_layout.addWidget(sector_group)

        # --- Access Bits Table ---
        self.access_table = QTableWidget(4, 5)  # 4 blocks per sector, 5 columns
        self.access_table.setHorizontalHeaderLabels(["Block", "Key A", "Access Bits", "Key B", "Access Rights"])
        self.access_table.verticalHeader().setVisible(False)
        self.access_table.setEditTriggers(QTableWidget.AllEditTriggers)
        main_layout.addWidget(QLabel("Access Conditions for Selected Sector"))
        main_layout.addWidget(self.access_table)
        self.sector_spin.valueChanged.connect(self.update_access_table)
        self.update_access_table()

        # --- Data Read/Write ---
        data_group = QGroupBox("Block Data")
        data_layout = QGridLayout()
        data_layout.addWidget(QLabel("Data:"), 0, 0)
        self.data_field = QLineEdit()
        self.data_field.setReadOnly(True)
        data_layout.addWidget(self.data_field, 0, 1, 1, 3)
        self.hex_ascii_toggle = QPushButton("HEX")
        self.hex_ascii_toggle.setCheckable(True)
        self.hex_ascii_toggle.setChecked(True)
        data_layout.addWidget(self.hex_ascii_toggle, 0, 4)
        self.read_btn = QPushButton("Read Block")
        self.write_btn = QPushButton("Write Block")
        data_layout.addWidget(self.read_btn, 1, 1)
        data_layout.addWidget(self.write_btn, 1, 2)
        data_group.setLayout(data_layout)
        main_layout.addWidget(data_group)

        self.read_btn.clicked.connect(self.read_block)
        self.write_btn.clicked.connect(self.write_block)
        self.hex_ascii_toggle.clicked.connect(self.toggle_hex_ascii)
        self.last_block_data = None

        # --- Access Bits Table (Placeholder) ---
        self.access_table = QTableWidget(8, 3)
        self.access_table.setHorizontalHeaderLabels(["Value", "keyA", "accessBits"])
        for i in range(8):
            self.access_table.setItem(i, 0, QTableWidgetItem(str(i)))
            self.access_table.setItem(i, 1, QTableWidgetItem("-"))
            self.access_table.setItem(i, 2, QTableWidgetItem("-"))
        main_layout.addWidget(QLabel("Access condition for sector trailer"))
        main_layout.addWidget(self.access_table)

        # --- Data Table (Placeholder) ---
        self.data_table = QTableWidget(16, 16)
        self.data_table.setHorizontalHeaderLabels([
            f"B{i}" for i in range(16)
        ])
        for i in range(16):
            for j in range(16):
                self.data_table.setItem(i, j, QTableWidgetItem(""))
        main_layout.addWidget(QLabel("Data Block (HEX)"))
        main_layout.addWidget(self.data_table)

        self.setLayout(main_layout)

    def refresh_readers(self):
        self.reader_combo.clear()
        try:
            self.available_readers = readers()
            if self.available_readers:
                for r in self.available_readers:
                    self.reader_combo.addItem(str(r))
                self.set_status_ready()
            else:
                self.reader_combo.addItem("No readers found")
                self.status_label.setText("Status: No device")
                self.status_label.setStyleSheet("color: red; font-weight: bold;")
        except Exception as e:
            self.reader_combo.addItem("Error listing readers")
            self.status_label.setText("Status: Error")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")

    def connect_reader(self):
        idx = self.reader_combo.currentIndex()
        if hasattr(self, 'available_readers') and self.available_readers and idx >= 0:
            try:
                self.selected_reader = self.available_readers[idx]
                self.set_status_connected()
            except Exception as e:
                self.status_label.setText("Status: Error")
                self.status_label.setStyleSheet("color: red; font-weight: bold;")
        else:
            self.status_label.setText("Status: No device")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")

    def set_status_ready(self):
        self.status_label.setText("Status: Device ready")
        self.status_label.setStyleSheet("color: orange; font-weight: bold;")

    def set_status_connected(self):
        self.status_label.setText("Status: Device connected")
        self.status_label.setStyleSheet("color: green; font-weight: bold;")

    def scan_card(self):
        self.uid_display.setText("")
        self.card_type_display.setText("")
        if not self.selected_reader:
            self.status_label.setText("Status: No reader connected")
            self.status_label.setStyleSheet("color: red;")
            return
        try:
            connection = self.selected_reader.createConnection()
            connection.connect()
            GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
            data, sw1, sw2 = connection.transmit(GET_UID)
            if (sw1, sw2) == (0x90, 0x00):
                uid = ' '.join(f'{b:02X}' for b in data)
                self.uid_display.setText(uid)
                self.card_type_display.setText("Mifare Classic 1K")
                self.status_label.setText("Status: Card read successfully")
                self.status_label.setStyleSheet("color: green;")
            else:
                self.uid_display.setText("")
                self.card_type_display.setText("")
                self.status_label.setText(f"Status: Command failed (SW1={sw1:02X} SW2={sw2:02X})")
                self.status_label.setStyleSheet("color: red;")
            connection.disconnect()
        except Exception as e:
            self.uid_display.setText("")
            self.card_type_display.setText("")
            self.status_label.setText(f"Status: {e}")
            self.status_label.setStyleSheet("color: red;")

    def update_selection_label(self):
        sector = self.sector_spin.value()
        block = self.block_spin.value()
        self.selection_label.setText(f"Current: Sector {sector}, Block {block}")

    def authenticate_a(self):
        self.authenticate_key(self.key_a_input.text(), key_type='A')

    def authenticate_b(self):
        self.authenticate_key(self.key_b_input.text(), key_type='B')

    def authenticate_key(self, key_str, key_type='A'):
        if not self.selected_reader:
            self.status_label.setText("Status: No device")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")
            return
        try:
            connection = self.selected_reader.createConnection()
            connection.connect()
            sector = self.sector_spin.value()
            block = self.block_spin.value()
            # Convert key string to bytes
            key_bytes = [int(x, 16) for x in key_str.strip().split()]
            if len(key_bytes) != 6:
                self.status_label.setText("Status: Invalid key")
                self.status_label.setStyleSheet("color: red; font-weight: bold;")
                return
            # APDU for authentication (Mifare Classic)
            # 0x60 = Key A, 0x61 = Key B
            key_code = 0x60 if key_type == 'A' else 0x61
            # Block number in absolute addressing
            block_num = sector * 4 + block
            apdu = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block_num, key_code, 0x00]
            # Load key into reader
            load_key_apdu = [0xFF, 0x82, 0x00, 0x00, 0x06] + key_bytes
            _, sw1, sw2 = connection.transmit(load_key_apdu)
            if (sw1, sw2) != (0x90, 0x00):
                self.status_label.setText(f"Status: Key load fail")
                self.status_label.setStyleSheet("color: red; font-weight: bold;")
                connection.disconnect()
                return
            _, sw1, sw2 = connection.transmit(apdu)
            if (sw1, sw2) == (0x90, 0x00):
                self.status_label.setText(f"Status: Auth {key_type} OK")
                self.status_label.setStyleSheet("color: green; font-weight: bold;")
            else:
                self.status_label.setText(f"Status: Auth {key_type} fail")
                self.status_label.setStyleSheet("color: red; font-weight: bold;")
            connection.disconnect()
        except Exception as e:
            self.status_label.setText(f"Status: Error")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")

    def update_access_table(self):
        sector = self.sector_spin.value()
        # Try to authenticate and read the sector trailer
        if not self.selected_reader:
            self.status_label.setText("Status: No device")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")
            for block in range(4):
                self.access_table.setItem(block, 0, QTableWidgetItem(str(block)))
                self.access_table.setItem(block, 1, QTableWidgetItem("-"))
                self.access_table.setItem(block, 2, QTableWidgetItem("-"))
                self.access_table.setItem(block, 3, QTableWidgetItem("-"))
                self.access_table.setItem(block, 4, QTableWidgetItem("-"))
            return
        try:
            connection = self.selected_reader.createConnection()
            connection.connect()
            # Use Key A for authentication by default
            key_str = self.key_a_input.text()
            key_bytes = [int(x, 16) for x in key_str.strip().split()]
            if len(key_bytes) != 6:
                raise ValueError("Invalid Key A")
            # Load Key A into reader
            load_key_apdu = [0xFF, 0x82, 0x00, 0x00, 0x06] + key_bytes
            _, sw1, sw2 = connection.transmit(load_key_apdu)
            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError("Key load fail")
            # Authenticate to sector trailer block (block 3 of sector)
            block_num = sector * 4 + 3
            auth_apdu = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block_num, 0x60, 0x00]
            _, sw1, sw2 = connection.transmit(auth_apdu)
            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError("Auth fail")
            # Read sector trailer block
            read_apdu = [0xFF, 0xB0, 0x00, block_num, 0x10]
            data, sw1, sw2 = connection.transmit(read_apdu)
            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError("Read fail")
            # Parse Key A, access bits, Key B
            key_a = ' '.join(f'{b:02X}' for b in data[:6])
            access_bytes = data[6:9]
            key_b = ' '.join(f'{b:02X}' for b in data[10:16])

            # Parse access bits for each block
            def parse_access_bits(access_bytes):
                # Returns a list of 4 tuples: (C1, C2, C3) for block 0-3
                c1 = []
                c2 = []
                c3 = []
                for i in range(4):
                    c1.append((access_bytes[1] >> (4 + i)) & 1)
                    c2.append((access_bytes[2] >> i) & 1)
                    c3.append((access_bytes[2] >> (4 + i)) & 1)
                return list(zip(c1, c2, c3))

            def mifare_rights(cbits, block):
                # Mifare Classic 1K: block 3 is sector trailer, 0-2 are data blocks
                rights = "?"
                if block < 3:
                    # Data block access conditions
                    table = {
                        (0,0,0): "Read: A/B, Write: A/B, Inc: A/B, Dec: A/B",
                        (0,1,0): "Read: A/B, Write: -, Inc: -, Dec: -",
                        (1,0,0): "Read: A/B, Write: B, Inc: B, Dec: A/B",
                        (1,1,0): "Read: A/B, Write: B, Inc: -, Dec: -",
                        (0,0,1): "Read: A/B, Write: -, Inc: -, Dec: -",
                        (0,1,1): "Read: B, Write: B, Inc: B, Dec: B",
                        (1,0,1): "Read: -, Write: -, Inc: -, Dec: -",
                        (1,1,1): "Read: B, Write: -, Inc: -, Dec: -",
                    }
                    rights = table.get(cbits, "?")
                else:
                    # Sector trailer access conditions
                    table = {
                        (0,0,0): "Key A: Read/Write, Access Bits: Write, Key B: Read/Write",
                        (0,1,0): "Key A: -, Access Bits: Write, Key B: Read/Write",
                        (1,0,0): "Key A: Read, Access Bits: -, Key B: Read",
                        (1,1,0): "Key A: -, Access Bits: -, Key B: Read",
                        (0,0,1): "Key A: Read/Write, Access Bits: Write, Key B: -",
                        (0,1,1): "Key A: -, Access Bits: Write, Key B: -",
                        (1,0,1): "Key A: Read, Access Bits: -, Key B: -",
                        (1,1,1): "Key A: -, Access Bits: -, Key B: -",
                    }
                    rights = table.get(cbits, "?")
                return rights

            cbits_list = parse_access_bits(access_bytes)

            for block in range(4):
                self.access_table.setItem(block, 0, QTableWidgetItem(str(block)))
                self.access_table.setItem(block, 1, QTableWidgetItem(key_a if block == 3 else "-"))
                self.access_table.setItem(block, 2, QTableWidgetItem(' '.join(f'{b:02X}' for b in access_bytes) if block == 3 else "-"))
                self.access_table.setItem(block, 3, QTableWidgetItem(key_b if block == 3 else "-"))
                # Show parsed rights for every block
                try:
                    rights = mifare_rights(cbits_list[block], block)
                except Exception:
                    rights = "?"
                self.access_table.setItem(block, 4, QTableWidgetItem(rights))
            self.status_label.setText("Status: Access bits read")
            self.status_label.setStyleSheet("color: green; font-weight: bold;")
            connection.disconnect()
        except Exception as e:
            self.status_label.setText(f"Status: Access bits fail: {e}")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")
            for block in range(4):
                self.access_table.setItem(block, 0, QTableWidgetItem(str(block)))
                self.access_table.setItem(block, 1, QTableWidgetItem("-"))
                self.access_table.setItem(block, 2, QTableWidgetItem("-"))
                self.access_table.setItem(block, 3, QTableWidgetItem("-"))
                self.access_table.setItem(block, 4, QTableWidgetItem("-"))

    def read_block(self):
        if not self.selected_reader:
            self.status_label.setText("Status: No device")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")
            return
        try:
            connection = self.selected_reader.createConnection()
            connection.connect()
            sector = self.sector_spin.value()
            block = self.block_spin.value()
            key_str = self.key_a_input.text()
            key_bytes = [int(x, 16) for x in key_str.strip().split()]
            if len(key_bytes) != 6:
                raise ValueError("Invalid Key A")
            # Load Key A
            load_key_apdu = [0xFF, 0x82, 0x00, 0x00, 0x06] + key_bytes
            _, sw1, sw2 = connection.transmit(load_key_apdu)
            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError("Key load fail")
            # Authenticate
            block_num = sector * 4 + block
            auth_apdu = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block_num, 0x60, 0x00]
            _, sw1, sw2 = connection.transmit(auth_apdu)
            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError("Auth fail")
            # Read block
            read_apdu = [0xFF, 0xB0, 0x00, block_num, 0x10]
            data, sw1, sw2 = connection.transmit(read_apdu)
            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError("Read fail")
            self.last_block_data = bytes(data)
            if self.hex_ascii_toggle.isChecked():
                self.data_field.setText(' '.join(f'{b:02X}' for b in data))
            else:
                try:
                    self.data_field.setText(bytes(data).decode('ascii', errors='replace'))
                except Exception:
                    self.data_field.setText('?')
            self.data_field.setReadOnly(False)
            self.status_label.setText("Status: Block read OK")
            self.status_label.setStyleSheet("color: green; font-weight: bold;")
            connection.disconnect()
        except Exception as e:
            self.status_label.setText(f"Status: Block read fail: {e}")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")
            self.data_field.setText("")
            self.data_field.setReadOnly(True)

    def write_block(self):
        if not self.selected_reader:
            self.status_label.setText("Status: No device")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")
            return
        try:
            connection = self.selected_reader.createConnection()
            connection.connect()
            sector = self.sector_spin.value()
            block = self.block_spin.value()
            key_str = self.key_a_input.text()
            key_bytes = [int(x, 16) for x in key_str.strip().split()]
            if len(key_bytes) != 6:
                raise ValueError("Invalid Key A")
            # Load Key A
            load_key_apdu = [0xFF, 0x82, 0x00, 0x00, 0x06] + key_bytes
            _, sw1, sw2 = connection.transmit(load_key_apdu)
            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError("Key load fail")
            # Authenticate
            block_num = sector * 4 + block
            auth_apdu = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block_num, 0x60, 0x00]
            _, sw1, sw2 = connection.transmit(auth_apdu)
            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError("Auth fail")
            # Prepare data
            if self.hex_ascii_toggle.isChecked():
                data_str = self.data_field.text().replace(' ', '')
                if len(data_str) != 32:
                    raise ValueError("Hex must be 16 bytes")
                data_bytes = bytes.fromhex(data_str)
            else:
                data_bytes = self.data_field.text().encode('ascii', errors='replace')
                if len(data_bytes) > 16:
                    raise ValueError("ASCII >16 bytes")
                data_bytes = data_bytes.ljust(16, b'\x00')
            # Write block
            write_apdu = [0xFF, 0xD6, 0x00, block_num, 0x10] + list(data_bytes)
            _, sw1, sw2 = connection.transmit(write_apdu)
            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError("Write fail")
            self.status_label.setText("Status: Block write OK")
            self.status_label.setStyleSheet("color: green; font-weight: bold;")
            connection.disconnect()
        except Exception as e:
            self.status_label.setText(f"Status: Block write fail: {e}")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")

    def toggle_hex_ascii(self):
        if self.last_block_data is None:
            return
        if self.hex_ascii_toggle.isChecked():
            self.hex_ascii_toggle.setText("HEX")
            self.data_field.setText(' '.join(f'{b:02X}' for b in self.last_block_data))
        else:
            self.hex_ascii_toggle.setText("ASCII")
            try:
                self.data_field.setText(self.last_block_data.decode('ascii', errors='replace'))
            except Exception:
                self.data_field.setText('?')

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MifareToolUI()
    window.show()
    sys.exit(app.exec_())
