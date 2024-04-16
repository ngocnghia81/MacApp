import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import pyperclip
import secrets
from abc import ABC, abstractmethod
from tkinter import simpledialog

class Caesar (ABC):
    def encrypt(self, text, s):
        result = ""

        text = str(text)
        for char in text:
            if char.isdigit():
                result += char
            
            elif char.isupper():
                result += chr((ord(char) + s - 65) % 26 + 65)

            elif char.islower():
                result += chr((ord(char) + s - 97) % 26 + 97)

            else:
                result += char

        return result


class MACApp(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        # self.master.title("MAC Demo App")
        self.FONT_SIZE = 12
        self.FONT_FAMILY = "Helvetica"
        self.create_widgets()
    

    def create_widgets(self):
        pass

    def generate_mac(self):
        pass

    def copy_mac(self):
        pass

    def verify_mac(self):
        pass


class MACUnencrypted(MACApp):
    def create_widgets(self):
        tk.Label(self.master, text="Secret Key:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.key_entry = tk.Entry(self.master, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.key_entry.grid(row=1, column=1, padx=5, pady=5)

        self.generate_key_button = tk.Button(self.master,text="Generate Secret Key",command=self.generate_secret_key,font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.generate_key_button.grid(row=2,column=1,padx=1,pady=1)

        tk.Label(self.master, text="Data:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.data_entry = tk.Entry(self.master, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.data_entry.grid(row=3, column=1, padx=5, pady=5)

        tk.Label(self.master, text="MAC:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.mac_label = tk.Label(self.master, text="", font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.mac_label.grid(row=4, column=1, padx=5, pady=5)

        self.generate_mac_button = tk.Button(self.master, text="Generate MAC", command=self.generate_mac, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.generate_mac_button.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

        self.copy_mac_button = tk.Button(self.master, text="Copy MAC", command=self.copy_mac, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.copy_mac_button.grid(row=5, column=1, padx=10, pady=5)

        tk.Label(self.master, text="MAC to Verify:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=7, column=0, padx=5, pady=5, sticky="w")
        self.mac_entry = tk.Entry(self.master, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.mac_entry.grid(row=9, column=1, padx=5, pady=5)

        self.verify_mac_button = tk.Button(self.master, text="Verify MAC", command=self.verify_mac, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.verify_mac_button.grid(row=9, column=0, columnspan=2, padx=5, pady=5)

    def generate_secret_key(self):
        secret_key = secrets.token_hex(32) 
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, secret_key)


    def generate_mac(self):
        if(self.key_entry.get()==""):
            messagebox.showerror("Error","The secret key cannot be empty")
        elif(self.data_entry.get()==""):
            messagebox.showerror("Error","The data cannot be empty")
        else:
            secret_key = self.key_entry.get().encode()
            data = self.data_entry.get().encode()

            mac = hmac.HMAC(secret_key, hashes.SHA256(), backend=default_backend())
            mac.update(data)
            mac_result = mac.finalize()

            self.mac_label.config(text=mac_result.hex())

    def copy_mac(self):
        mac_to_copy = self.mac_label.cget("text")
        pyperclip.copy(mac_to_copy)

    def verify_mac(self):
        secret_key = self.key_entry.get().encode()
        data = self.data_entry.get().encode()
        mac_input = self.mac_entry.get()

        try:
            mac = bytes.fromhex(mac_input)
        except ValueError:
            messagebox.showerror("Error", "Invalid MAC format")
            return

        mac_validator = hmac.HMAC(secret_key, hashes.SHA256(), backend=default_backend())
        mac_validator.update(data)
        
        try:
            mac_validator.verify(mac)
            messagebox.showinfo("Result", "MAC is valid. Data integrity verified.\n")
        except Exception:
            messagebox.showerror("Result", "MAC is invalid. Data integrity compromised.")


class MACEncryptedPlainText(MACApp,Caesar):
    def create_widgets(self):
        tk.Label(self.master, text="Secret Key:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.key_entry = tk.Entry(self.master, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.key_entry.grid(row=1, column=1, padx=5, pady=5)

        self.generate_key_button = tk.Button(self.master,text="Generate Secret Key",command=self.generate_secret_key,font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.generate_key_button.grid(row=2,column=1,padx=1,pady=1)

        tk.Label(self.master, text="Shift:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.shift = tk.Entry(self.master, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.shift.grid(row=3, column=1, padx=5, pady=5)

        self.generate_key_button = tk.Button(self.master,text="Generate shift",command=self.generate_shift,font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.generate_key_button.grid(row=4,column=1,padx=1,pady=1)

        tk.Label(self.master, text="Data:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=5, column=0, padx=5, pady=5, sticky="w")
        self.data_entry = tk.Entry(self.master, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.data_entry.grid(row=5, column=1, padx=5, pady=5)

        tk.Label(self.master, text="MAC:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=6, column=0, padx=5, pady=5, sticky="w")
        self.mac_label = tk.Label(self.master, text="", font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.mac_label.grid(row=6, column=1, padx=5, pady=5)

        tk.Label(self.master, text="Encrypted MAC:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=7, column=0, padx=5, pady=5, sticky="w")
        self.encrypted_mac_label = tk.Label(self.master, text="", font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.encrypted_mac_label.grid(row=7, column=1, padx=5, pady=5)

        self.generate_mac_button = tk.Button(self.master, text="Generate", command=self.generate_mac, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.generate_mac_button.grid(row=8, column=0, columnspan=2, padx=10, pady=5)

        self.copy_mac_button = tk.Button(self.master, text="Copy MAC", command=self.copy_mac, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.copy_mac_button.grid(row=8, column=1, padx=5, pady=5)

        tk.Label(self.master, text="MAC to Verify:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=9, column=0, padx=5, pady=5, sticky="w")
        self.mac_entry = tk.Entry(self.master, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.mac_entry.grid(row=9, column=1, padx=5, pady=5)

        self.verify_mac_button = tk.Button(self.master, text="Verify MAC", command=self.verify_mac, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.verify_mac_button.grid(row=10, column=0, columnspan=2, padx=5, pady=5)

    def generate_secret_key(self):
        secret_key = secrets.token_hex(32) 
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, secret_key)

    def generate_shift(self):
        secret_key = secrets.randbelow(25) + 1
        self.shift.delete(0, tk.END)
        self.shift.insert(0, secret_key)

    def generate_mac(self):
        if(self.key_entry.get()==""):
            messagebox.showerror("Error","The secret key cannot be empty")
        elif(self.shift.get()==""):
            messagebox.showerror("Error","The shift cannot be empty")
        elif(self.data_entry.get()==""):
            messagebox.showerror("Error","The data cannot be empty")
        elif(not self.shift.get().isdigit()):
            messagebox.showerror("Error","The shift must be digit")
        else:
            secret_key = self.key_entry.get().encode()
            data = self.data_entry.get().encode()
            mac = hmac.HMAC(secret_key, hashes.SHA256(), backend=default_backend())
            mac.update(data)
            mac_result = mac.finalize()
            self.mac_label.config(text=mac_result.hex())
            self.encrypted_mac_label.config(text=self.encrypt_data(str(mac_result.hex())))
    
    def copy_mac(self):
        mac_to_copy = self.encrypted_mac_label.cget("text")
        pyperclip.copy(mac_to_copy)

    def verify_mac(self):
        mac = self.encrypt(self.mac_entry.get(),26-int(self.shift.get()))
        print(mac.encode())
        secret_key = self.key_entry.get().encode()
        # secret_key2 = self.shift.get().encode()
        data = self.data_entry.get().encode()
        # mac_input = self.mac_label.get()

        try:
            mac = bytes.fromhex(mac)
        except ValueError:
            messagebox.showerror("Error", "Invalid MAC format")
            return


        mac_validator = hmac.HMAC(secret_key, hashes.SHA256(), backend=default_backend())
        mac_validator.update(data)

        try:
            mac_validator.verify(mac)
            messagebox.showinfo("Result", "MAC is valid. Data integrity verified.")
        except Exception:
            messagebox.showerror("Result", "MAC is invalid. Data integrity compromised.")

    def encrypt_data(self, data):
        shift = int(self.shift.get())
        encrypted_data = self.encrypt(data,shift)
        return encrypted_data


class MACEncryptedCipherText(MACApp,Caesar):
    def create_widgets(self):
        tk.Label(self.master, text="Secret Key:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.key_entry = tk.Entry(self.master, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.key_entry.grid(row=1, column=1, padx=5, pady=5)

        self.generate_key_button = tk.Button(self.master,text="Generate Secret Key",command=self.generate_secret_key,font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.generate_key_button.grid(row=2,column=1,padx=1,pady=1)

        tk.Label(self.master, text="Shift:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.shift = tk.Entry(self.master, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.shift.grid(row=3, column=1, padx=5, pady=5)

        self.generate_key_button = tk.Button(self.master,text="Generate shift",command=self.generate_shift,font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.generate_key_button.grid(row=4,column=1,padx=1,pady=1)

        tk.Label(self.master, text="Data:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=5, column=0, padx=5, pady=5, sticky="w")
        self.data_entry = tk.Entry(self.master, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.data_entry.grid(row=5, column=1, padx=5, pady=5)

        self.encrypted_data_button = tk.Button(self.master, text="Encrypt", command=self.encrypt_message, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.encrypted_data_button.grid(row=6, column=0, columnspan=2, padx=10, pady=5)

        tk.Label(self.master, text="Encrypted data:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=7, column=0, padx=5, pady=5, sticky="w")
        self.encrypted_data = tk.Label(self.master, text="", font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.encrypted_data.grid(row=7, column=1, padx=5, pady=5)

        self.encrypted_data_button = tk.Button(self.master, text="Edit encrypted data", command=self.edit_encrypted_data, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.encrypted_data_button.grid(row=8, column=1, padx=5, pady=5)

        tk.Label(self.master, text="MAC:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=9, column=0, padx=5, pady=5, sticky="w")
        self.mac_label = tk.Label(self.master, text="", font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.mac_label.grid(row=9, column=1, padx=5, pady=5)

        self.generate_mac_button = tk.Button(self.master, text="Generate", command=self.generate_mac, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.generate_mac_button.grid(row=10, column=0, columnspan=2, padx=10, pady=5)

        self.copy_mac_button = tk.Button(self.master, text="Copy MAC", command=self.copy_mac, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.copy_mac_button.grid(row=10, column=1, padx=5, pady=5)

        tk.Label(self.master, text="MAC to Verify:", font=(self.FONT_FAMILY, self.FONT_SIZE)).grid(row=10, column=0, padx=5, pady=5, sticky="w")
        self.mac_entry = tk.Entry(self.master, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.mac_entry.grid(row=11, column=1, padx=5, pady=5)

        self.verify_mac_button = tk.Button(self.master, text="Verify MAC", command=self.verify_mac, font=(self.FONT_FAMILY, self.FONT_SIZE))
        self.verify_mac_button.grid(row=12, column=0, columnspan=2, padx=5, pady=5)

    def generate_secret_key(self):
        secret_key = secrets.token_hex(32) 
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, secret_key)

    def generate_shift(self):
        secret_key = secrets.randbelow(25) + 1
        self.shift.delete(0, tk.END)
        self.shift.insert(0, secret_key)

    def generate_mac(self):
        if(self.key_entry.get()==""):
            messagebox.showerror("Error","The secret key cannot be empty")
        elif(self.shift.get()==""):
            messagebox.showerror("Error","The shift cannot be empty")
        elif(self.data_entry.get()==""):
            messagebox.showerror("Error","The data cannot be empty")
        elif(not self.shift.get().isdigit()):
            messagebox.showerror("Error","The shift must be digit")
        elif(self.encrypted_data.cget("text")==""):
            messagebox.showerror("Error","Must encrypt data before creating MAC")
        else:
            secret_key = self.key_entry.get().encode()
            data = self.encrypted_data.cget("text").encode()
            mac = hmac.HMAC(secret_key, hashes.SHA256(), backend=default_backend())
            mac.update(data)
            mac_result = mac.finalize()
            self.mac_label.config(text=mac_result.hex())
    
    def copy_mac(self):
        mac_to_copy = self.mac_label.cget("text")
        pyperclip.copy(mac_to_copy)
    
    def edit_encrypted_data(self):
        editInput = simpledialog.askstring("Edit encrypted data","Encrypted data:")

        if editInput is not None:
            self.encrypted_data.config(text=editInput)

    def verify_mac(self):
        # mac = self.encrypt(self.mac_entry.get(),int(self.shift.get()))
        secret_key = self.key_entry.get().encode()
        # secret_key2 = self.shift.get().encode()
        data = self.encrypted_data.cget("text").encode()
        # mac_input = self.mac_label.get()

        try:
            mac = bytes.fromhex(self.mac_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid MAC format")
            return

        mac_validator = hmac.HMAC(secret_key, hashes.SHA256(), backend=default_backend())
        mac_validator.update(data)
        message = self.encrypt(self.encrypted_data.cget("text"),26 - int(self.shift.get()))

        try:
            mac_validator.verify(mac)
            messagebox.showinfo("Result", "MAC is valid. Data integrity verified.\n"+"Data: "+message)
        except Exception:
            messagebox.showerror("Result", "MAC is invalid. Data integrity compromised.")

    def encrypt_message(self):
        self.encrypt_data(self.data_entry.get())

    def encrypt_data(self, data):
        shift = int(self.shift.get())
        encrypted_data = self.encrypt(data,shift)
        self.encrypted_data.config(text=encrypted_data)
        return encrypted_data


class MACApplication(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.title("MAC Demo App")
        self.FONT_SIZE = 12
        self.FONT_FAMILY = "Helvetica"
        self.mode = tk.IntVar()  
        self.mode.set(0)  
        self.create_widgets()
        self.select_mode()
        self.app = None
        self.master.resizable(width=False, height=False)

    def create_widgets(self):
        self.mac_unencrypted_button = tk.Radiobutton(self.master, text="MAC Unencrypted", variable=self.mode, value=1, command=self.set_mode)
        self.mac_unencrypted_button.grid(row=0, column=0)

        self.mac_encrypted_origin_button = tk.Radiobutton(self.master, text="MAC Encrypted Plain text", variable=self.mode, value=2, command=self.set_mode)
        self.mac_encrypted_origin_button.grid(row=0, column=1)

        self.mac_encrypted_mac_button = tk.Radiobutton(self.master, text="MAC Encrypted Cipher text", variable=self.mode, value=3, command=self.set_mode)
        self.mac_encrypted_mac_button.grid(row=0, column=2)

        self.mac_app_frame = tk.Frame(self.master)
        self.mac_app_frame.grid(row=1, column=0, columnspan=3)

    def set_mode(self):
        self.mode.set(self.get_selected_mode())
        self.select_mode()

    def select_mode(self):
        self.clear_frame(self.mac_app_frame)
        mode = self.get_selected_mode()
        if mode == 0:
            self.clear_frame()
        elif mode == 1:
            self.app = MACUnencrypted(self.mac_app_frame)
        elif mode == 2:
            self.app = MACEncryptedPlainText(self.mac_app_frame)
        elif mode == 3:
            self.app = MACEncryptedCipherText(self.mac_app_frame)

    def get_selected_mode(self):
        return self.mode.get()

    def clear_frame(self, frame=None):
        if frame:
            for widget in frame.winfo_children():
                widget.destroy()


root = tk.Tk()
app = MACApplication(master=root)
app.mainloop()

