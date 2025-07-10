import datetime
import re
import tkinter as tk
from tkinter import messagebox, filedialog
from datetime import datetime as dt

def validate_field(value: str, code: str) -> bool:
    value = value.strip()
    if not value:
        return False

    if code == 'A':
        return bool(re.fullmatch(r'[A-Za-z]+', value))
    elif code == 'N':
        return bool(re.fullmatch(r'\d+', value))
    elif code.startswith('S('):
        specials = code[2:-1]
        pattern = f'[{re.escape(specials)}]+'
        return bool(re.fullmatch(pattern, value))
    elif code == 'AN':
        return bool(re.fullmatch(r'[A-Za-z0-9]+', value))
    elif code.startswith('ANS'):
        if code == 'ANS':
            return bool(re.fullmatch(r'[\w\s\W]+', value))
        else:
            specials = code[4:-1]
            allowed_chars = r'A-Za-z0-9' + re.escape(specials) + r'\s'
            pattern = f'[{allowed_chars}]+'
            return bool(re.fullmatch(pattern, value))
    else:
        return False

def generate_filename(cic: str, seq: int) -> str:
    now = datetime.datetime.now()
    date_str = now.strftime('%Y%m%d')
    time_str = now.strftime('%H%M%S')
    filename = f"SO_Message_{date_str}_{time_str}_{cic}_{seq}.txt"
    return filename

def generate_header_line(customer_code, user_id, email=''):
    customer_code = customer_code.strip()
    if not (3 <= len(customer_code) <= 5):
        raise ValueError("Customer Identification Code must be between 3 and 5 characters")
    if not validate_field(customer_code, 'AN'):
        raise ValueError("Customer Identification Code must be alphanumeric only (A-Z, 0-9)")

    user_id = user_id.strip()
    if not (4 <= len(user_id) <= 30):
        raise ValueError("User ID must be between 4 and 30 characters")
    allowed_specials = r"\-\(\)@\$^\-_+\~`\{\[\]\}\\|:;\"’<,\.>"
    user_id_pattern = f'^[A-Za-z0-9{allowed_specials}]+$'
    if not re.fullmatch(user_id_pattern, user_id):
        raise ValueError("User ID contains invalid characters")

    email = email.strip()
    if email:
        if not (7 <= len(email) <= 100):
            raise ValueError("Email address must be between 7 and 100 characters")
        if not re.match(r'^[a-zA-Z0-9._\-@#]+$', email):
            raise ValueError("Email address contains invalid characters")

    record_identifier = "FH"
    version = "ARSOUploadv2.0"

    fields = [
        record_identifier,
        version,
        customer_code,
        user_id,
        email
    ]

    return '|'.join(fields) + '|'

def validate_record_line(fields):
    print(f"DEBUG validate_record_line received fields: {fields}")
    fields = [f.strip() for f in fields]  # Strip all fields first
    if len(fields) < 11:
        return False, "Record must have at least 11 fields"

    if fields[0] != "HH":
        return False, "RecordIdentifier must be 'HH'"

    supplier_code = fields[1].strip()
    print(f"Supplier Code: '{supplier_code}'")
    if len(supplier_code) != 5 or not re.fullmatch(r'[A-Za-z0-9]{5}', supplier_code):
        return False, "SupplierCageCode must be exactly 5 alphanumeric chars"

    if not (1 <= len(fields[2]) <= 32) or not fields[2].isdigit():
        return False, "MessageSeqID must be numeric 1 to 32 digits"

    try:
        dt.strptime(fields[3], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False, "CreationDateTime must be in YYYY-MM-DD HH:MM:SS format"

    allowed_specials = r"\-\(\)@\$^\-_+\~`\{\[\]\}\\|:;\"’<,\.>"
    pattern = f'^[A-Za-z0-9{allowed_specials}]+$'
    id_val = fields[4]
    if not (4 <= len(id_val) <= 30) or not re.fullmatch(pattern, id_val):
        return False, "ID must be 4-30 chars with allowed characters"

    if not re.fullmatch(r'\d', fields[5]):
        return False, "OrderType must be a single digit"

    if fields[6] not in ("N","C","X"):
        return False, "TransactionType must be 'N', 'C', or 'X'"

    if not re.fullmatch(r'^[A-Za-z0-9\- ]{1,25}$', fields[7]):
        return False, "ServiceOrderNumber invalid format"

    if not re.fullmatch(r'^[A-Za-z0-9\.\-\/\|\*]{1,32}$', fields[8]):
        return False, "PartNumber invalid format"

    mcode = fields[9]
    if mcode and (len(mcode) != 5 or not re.fullmatch(r'[A-Za-z0-9]{5}', mcode)):
        return False, "ManufacturerCode must be exactly 5 alphanumeric chars if present"

    if not re.fullmatch(r'\d{1,5}', fields[10]):
        return False, "OrderQuantity must be numeric 1 to 5 digits"

    return True, ""

def write_flat_file(records, cic, seq, filepath, customer_code, user_id, email=''):
    max_records = 1_000_000
    if len(records) > max_records:
        records = records[:max_records]

    with open(filepath, 'w', newline='') as f:
        header_line = generate_header_line(customer_code, user_id, email)
        f.write(header_line + '\r\n')

        for idx, record in enumerate(records):
            valid, msg = validate_record_line(record)
            if not valid:
                raise ValueError(f"Record line {idx+1} error: {msg}")

            trimmed = [str(field).strip() if field is not None else '' for field in record]
            line = '|'.join(trimmed) + '|'
            f.write(line + '\r\n')

def set_entry_valid(entry_widget, is_valid):
    entry_widget.config(bg='white' if is_valid else '#FFC0C0')

def limit_size_entry(max_len):
    def callback(P):
        return len(P) <= max_len
    return callback

def on_generate():
    try:
        cic = entry_cic.get().strip()
        seq = int(entry_seq.get())
        customer_code = entry_customer_code.get()
        user_id = entry_user_id.get()
        email = entry_email.get()
        raw_text = text_records.get("1.0", tk.END).strip()

        if not cic:
            messagebox.showerror("Error", "CIC cannot be empty")
            return

        valid_customer = bool(customer_code) and validate_field(customer_code, 'AN') and (3 <= len(customer_code) <= 5)
        set_entry_valid(entry_customer_code, valid_customer)
        if not valid_customer:
            messagebox.showerror("Error", "Customer Identification Code is required, must be 3-5 alphanumeric characters")
            return

        allowed_specials = r"\-\(\)@\$^\-_+\~`\{\[\]\}\\|:;\"’<,\.>"
        user_id_pattern = f'^[A-Za-z0-9{allowed_specials}]+$'
        valid_userid = bool(user_id) and re.fullmatch(user_id_pattern, user_id) and (4 <= len(user_id) <= 30)
        set_entry_valid(entry_user_id, valid_userid)
        if not valid_userid:
            messagebox.showerror("Error", "User ID is required, must be 4-30 characters and contain only allowed characters")
            return

        email = email.strip()
        if email and (not (7 <= len(email) <= 100) or not re.match(r'^[a-zA-Z0-9._\-@#]+$', email)):
            messagebox.showerror("Error", "Email address must be 7-100 chars and contain only allowed characters")
            return
        set_entry_valid(entry_email, True)

        raw_lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
        if not raw_lines:
            messagebox.showerror("Error", "Please enter at least one record")
            return

        records = []
        for line in raw_lines:
            # Normalize delimiter to always split by '|'
            normalized_line = line.replace(',', '|')
            fields = [f.strip() for f in normalized_line.split('|')]
            print(f"DEBUG on_generate split fields: {fields}")
            if len(fields) < 11:
                fields += [''] * (11 - len(fields))
            records.append(fields)

        default_filename = generate_filename(cic, seq)
        filepath = filedialog.asksaveasfilename(
            title="Save Flat File",
            defaultextension=".txt",
            initialfile=default_filename,
            filetypes=[("Text files", "*.txt")]
        )
        if not filepath:
            return

        write_flat_file(records, cic, seq, filepath, customer_code, user_id, email)
        messagebox.showinfo("Success", f"Flat file generated:\n{filepath}")

        set_entry_valid(entry_customer_code, True)
        set_entry_valid(entry_user_id, True)
        set_entry_valid(entry_email, True)

    except ValueError as ve:
        messagebox.showerror("Error", str(ve))

root = tk.Tk()
root.title("Flat File Generator")

vcmd_customer = (root.register(limit_size_entry(5)), '%P')
vcmd_userid = (root.register(limit_size_entry(30)), '%P')
vcmd_email = (root.register(limit_size_entry(100)), '%P')

tk.Label(root, text="CIC Code:").grid(row=0, column=0, sticky="w")
entry_cic = tk.Entry(root)
entry_cic.grid(row=0, column=1, pady=5, padx=5)
entry_cic.insert(0, "QF2")

tk.Label(root, text="Sequence Number:").grid(row=1, column=0, sticky="w")
entry_seq = tk.Entry(root)
entry_seq.grid(row=1, column=1, pady=5, padx=5)
entry_seq.insert(0, "1")

tk.Label(root, text="Customer Identification Code (3-5 chars):").grid(row=2, column=0, sticky="w")
entry_customer_code = tk.Entry(root, validate='key', validatecommand=vcmd_customer)
entry_customer_code.grid(row=2, column=1, pady=5, padx=5)

tk.Label(root, text="User ID (4-30 chars):").grid(row=3, column=0, sticky="w")
entry_user_id = tk.Entry(root, validate='key', validatecommand=vcmd_userid)
entry_user_id.grid(row=3, column=1, pady=5, padx=5)

tk.Label(root, text="Email Address (optional):").grid(row=4, column=0, sticky="w")
entry_email = tk.Entry(root, validate='key', validatecommand=vcmd_email)
entry_email.grid(row=4, column=1, pady=5, padx=5)

tk.Label(root, text="Enter Records (one per line, fields separated by | or ,):").grid(row=5, column=0, columnspan=2, sticky="w")

text_records = tk.Text(root, width=60, height=15)
text_records.grid(row=6, column=0, columnspan=2, pady=5, padx=5)

btn_generate = tk.Button(root, text="Generate Flat File", command=on_generate)
btn_generate.grid(row=7, column=0, columnspan=2, pady=10)

root.mainloop()
