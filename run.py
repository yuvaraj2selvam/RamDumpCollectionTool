import tkinter as tk
import tkinter.messagebox
import customtkinter
import frida
import sys
import os
import re
import string
import shutil
import psutil
from tkinter import filedialog
from cryptography.fernet import Fernet
import getpass
from tkinter import Label
from PIL import Image, ImageOps
from PIL import ImageTk
import cryptography
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
import base64



customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"



def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    encrypted_file_path = file_path + ".encrypted"
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

def decrypt_file(encrypted_file_path, key):
    fernet = Fernet(key)
    with open(encrypted_file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    decrypted_file_path = encrypted_file_path.replace(".encrypted", "")
    with open(decrypted_file_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # configure window
        self.key = None
        self.title("Ram Dump Tool")
        #580
        self.geometry(f"{1000}x{580}")

        self.resizable(True, True)

        # configure grid layout (4x4)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3,4), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        # create sidebar frame with widgets
        self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)
        self.right_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)

        self.right_frame.grid(row=0, column=3, rowspan=8, sticky="nsew")
        self.right_frame.grid_rowconfigure(8, weight=1)
       
        self.sidebar_frame.grid(row=0, column=0, rowspan=8, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(8, weight=1)
       
        self.logo_label1 = customtkinter.CTkLabel(self.sidebar_frame, text="Dump Memory", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label1.grid(row=0, column=0, padx=20, pady=(40, 20))
       
        self.sidebar_button_1 = customtkinter.CTkButton(self.sidebar_frame, text="Select process", command=self.show_process_list)

        self.sidebar_button_1.grid(row=1, column=0, padx=20, pady=15)
       
        self.sidebar_button_2 = customtkinter.CTkButton(self.sidebar_frame, text="Select Location", command=self.select_output_location)
        self.sidebar_button_2.grid(row=2, column=0, padx=20, pady=15)
       
        self.logo_label2 = customtkinter.CTkLabel(self.sidebar_frame, text="Encrypt/Decrypt", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label2.grid(row=3, column=0, padx=20, pady=(40, 20))
       
        # self.entry2 = customtkinter.CTkEntry(self.sidebar_frame, placeholder_text="Password")
        # self.entry2.grid(row=4, column=0, padx=20, pady=15)
       
        self.encrypt_button = customtkinter.CTkButton(self.sidebar_frame, text="Encrypt Directory", command=self.encrypt_directory)
        self.encrypt_button.grid(row=5, column=0, padx=20, pady=15)

        self.decrypt_button = customtkinter.CTkButton(self.sidebar_frame, text="Decrypt Directory", command=self.decrypt_directory)
        self.decrypt_button.grid(row=6, column=0, padx=20, pady=15)
       
        self.logo_label2 = customtkinter.CTkLabel(self.right_frame, text="Dump Analyzer", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label2.grid(row=0, column=3, padx=20, pady=(40, 20))

        self.sidebar_button_3 = customtkinter.CTkButton(self.right_frame, text="Select Dump File", command=self.select_input_location)
        self.sidebar_button_3.grid(row=1, column=3, padx=20, pady=15)

        self.entry0 = customtkinter.CTkEntry(self.right_frame, placeholder_text="Search Pattern")
        self.entry0.grid(row=2, column=3, padx=20, pady=15)

        self.sidebar_button_4 = customtkinter.CTkButton(self.right_frame, text="Analyze", command=self.analyze_location)
        self.sidebar_button_4.grid(row=3, column=3, padx=20, pady=15)


        self.sidebar_button_5 = customtkinter.CTkButton(self.right_frame, text="Exit", command=self.quit)
        self.sidebar_button_5.grid(row=4, column=3, padx=20, pady=15)
       
        self.appearance_mode_label = customtkinter.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=9, column=0, padx=20, pady=10)

        self.appearance_mode_optionmenu = customtkinter.CTkOptionMenu(self.sidebar_frame, values=["Light", "Dark", "System"],
                                                                      command=self.change_appearance_mode_event)
        self.appearance_mode_optionmenu.grid(row=10, column=0, padx=20, pady=10)

        # create main entry and button
        self.entry1 = customtkinter.CTkEntry(self, placeholder_text="Process ID/Name")
        self.entry1.grid(row=3, column=1, columnspan=1, padx=(20, 20), pady=(20, 20), sticky="nsew")

        self.main_button_1 = customtkinter.CTkButton(master=self, text="Dump", command=self.dump_memory,font=customtkinter.CTkFont(weight="bold"), border_width=2, text_color=("gray10", "#DCE4EE"))
        self.main_button_1.grid(row=3, column=3, padx=(20, 20), pady=(20, 20), sticky="nsew")

        self.appearance_mode_optionmenu.set("Dark")

        image_path = "/home/yuvarj2selvam/Desktop/RamDumpTool/tiknter/res/ram.jpg" 
        image = Image.open(image_path)
        self.image = image.resize((1000, 700))  
        self.photo = ImageTk.PhotoImage(image)
        high_res_image = Image.open(image_path)
        self.high_res_image = high_res_image.resize((1000, 700))
         
        self.image_label = Label(self, image=self.photo)
        self.image_label.grid(row=0, rowspan=3, column=1, columnspan=2, padx=10, pady=10)

        self.bind("<Configure>", self.update_image_size)


    def open_input_dialog_event(self):
        dialog = customtkinter.CTkInputDialog(text="Type in a number:", title="CTkInputDialog")
        print("CTkInputDialog:", dialog.get_input())

    def change_appearance_mode_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)
   
    def update_image_size(self, event):
        new_width = event.width
        new_height = int(new_width * (700 / 1000))  # Maintain the aspect ratio of the image
        resized_image = ImageOps.fit(self.high_res_image, (new_width, new_height), method=0, bleed=0.0, centering=(0.5, 0.5))
        self.photo = ImageTk.PhotoImage(resized_image)
        self.image_label.config(image=self.photo)
        self.image_label.image = self.photo

    def select_output_location(self):
        output_dir = filedialog.askdirectory()  
        if output_dir:
            print("Output Location:", output_dir)
            self.output = output_dir

    def generate_key(self, password):
        salt = os.urandom(16)  
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,  
            salt=salt,
            length=32 
        )
        key = kdf.derive(password.encode())
        base64_key = base64.urlsafe_b64encode(key)  # Convert the key to base64
        return base64_key

    def save_key(self, key):
        key_directory = filedialog.askdirectory()
        if key_directory:
            key_file_path = os.path.join(key_directory, "encryption_key.txt")
            with open(key_file_path, 'wb') as key_file:
                key_file.write(key)
            self.show_message("Key saved successfully.")
        else:
            self.show_message("No key storage directory selected.")

    def encrypt_directory(self):
        output_dir = filedialog.askdirectory()
        output = output_dir
        print("Encrypting directory :", output)
        password = ""
        print("Password :", password)
        key = self.generate_key(password)
        print("Encryption Key:", key)  # Print the key for debugging

        for root, dirs, files in os.walk(output):
            for file in files:
                file_path = os.path.join(root, file)
                encrypt_file(file_path, key)
                os.remove(file_path) 
        self.save_key(key)        
        self.show_message("Encryption completed successfully.")
        print("Encryption completed successfully.")

    def fetch_key(self):
        key_file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if key_file_path:
            print("Selected key file:", key_file_path)  # Debug statement

            try:
                with open(key_file_path, 'rb') as key_file:
                    key = key_file.read()
                return key
            except FileNotFoundError:
                self.show_message("Key file not found.")
                return None
        else:
            self.show_message("No key file selected.")
            return None

    def decrypt_directory(self):
        output_dir = filedialog.askdirectory()
        output = output_dir
        print("Decrypting directory:", output)
       
        # Fetch the key from the stored location
        key = self.fetch_key()

        if key:
            print("Decryption key:", key)

            decryption_failed = False

            for root, dirs, files in os.walk(output):
                for file in files:
                    if file.endswith(".encrypted"):
                        file_path = os.path.join(root, file)
                        try:
                            decrypt_file(file_path, key)
                            os.remove(file_path)  # Remove the encrypted file
                        except cryptography.fernet.InvalidToken:
                            print(f"Decryption failed for file: {file_path}")
                            decryption_failed = True

            if decryption_failed:
                self.show_message("Decryption failed: Invalid password or corrupted data.")
                print("Decryption failed: Invalid password or corrupted data.")
            else:
                self.show_message("Decryption completed successfully.")
                print("Decryption completed successfully.")


    def select_input_location(self):
        input_dir = filedialog.askdirectory()  
        if input_dir:
            print("Input Location:", input_dir)
            self.input = input_dir            
   
    def extract_strings(self,filename, min_length=4):
        with open(filename, "rb") as f:
            content = f.read()

        printable_strings = []
        current_string = ""

        for byte in content:
            if chr(byte) in string.printable:
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    printable_strings.append(current_string)
                current_string = ""

        return printable_strings

    def grep_strings(self,strings, pattern):
        return [s for s in strings if re.search(pattern, s)]

    def analyze_location(self):
        pattern = self.entry0.get()

        if hasattr(self, 'input') and self.input:
            input = self.input
            print("Dump Files Location:", input)
            print("Searching Pattern:",pattern)
            directory = input
            files = os.listdir(directory)
            for filename in files:
                filepath = os.path.join(directory, filename)
               
                strings = self.extract_strings(filepath, 4)  

                if pattern:  
                    matched_strings = self.grep_strings(strings, pattern)  # Use self.grep_strings
                    for s in matched_strings:
                        print(s)
                else:
                    for s in strings:
                        print(s)

            print("Patter Search Successfull")        
            self.show_message("Pattern Seacrh Successfull")    
        else:
            tkinter.messagebox.showinfo("Error", "Location Not Selected, Select the Dump Files Location")
       
       
    def show_message(self, message):
        tkinter.messagebox.showinfo("Message", message)

    def attach(self):
        process = self.entry1.get()
        try:
            session = frida.attach(process)
        except frida.ProcessNotFoundError:
            return None
        return session

    def show_process_list(self):
        process_list_window = ProcessListWindow(self)
        process_list_window.show_running_processes()    

    def dump_memory(self):
       
        if hasattr(self, 'output') and self.output:
            output = self.output
            process = self.entry1.get().strip()  
            print('Dumping %s memory.' % process)

            try:
                proc = int(process)
                process_name = None
            except ValueError:
                proc = None
                process_name = process

            if not os.path.isabs(output):
                output = os.path.join(os.path.dirname(os.path.realpath(__file__)), output)
            try:
                os.makedirs(output, exist_ok=True)
            except OSError as error:
                pass

            if sys.platform == "win32":
                output = output.replace('\\', '/')

            print(output)
            session = None

            if proc is not None:
                try:
                    session = frida.attach(proc)
                except frida.ProcessNotFoundError:
                    pass
            elif process_name is not None:
                session = frida.attach(process_name)

            if session is None:
                error_message = "Process not found or running. Please enter a valid process ID or name."
                print(error_message)
                tkinter.messagebox.showinfo("Error", error_message)
                return
            if proc is not None:
                target = proc
            elif process_name is not None:
                target = process_name
            else:
                error_message = "No process ID or name specified. Please enter a valid process ID or name."
                print(error_message)
                tkinter.messagebox.showinfo("Error", error_message)
                return

            protection = "r--"
            script = session.create_script("""
            function storeArrayBuffer(filename, buffer) {
                console.log(filename);
                var destFileName = new File(filename, "wb");
                destFileName.write(buffer);
                destFileName.flush();
                destFileName.close();
            }
           
            var ranges = Process.enumerateRangesSync({protection: '%s', coalesce: true});
            var totalRanges = ranges.length;
            var failedDumps = 0;
            console.log('[BEGIN] Located ' + totalRanges + ' memory ranges matching [' + '%s' + ']');
            ranges.forEach(function (range) {
                var destFileName = '%s/'.concat(range.base, "_dump");
                var arrayBuf;
                try {
                    arrayBuf = range.base.readByteArray(range.size);
                } catch (e) {
                    failedDumps += 1;
                    return;
                }
                if (arrayBuf) {
                    storeArrayBuffer(destFileName, arrayBuf);
                }
            });
            var successfulDumps = totalRanges - failedDumps;
            console.log("[FINISH] Successfully dumped ".concat(successfulDumps, "/").concat(totalRanges, " ranges."));
            """ % (protection, protection, output))
            script.load()
            session.detach()
            self.show_message("Memory dump completed successfully.")
            pass
       
        else:    
           tkinter.messagebox.showinfo("Error", "No output location selected. Please select an output location.")
       
class ProcessListWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)

        self.title("Select Process")
        self.geometry("300x300")

        self.scrollbar = tk.Scrollbar(self)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.process_listbox = tk.Listbox(self, yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.process_listbox.yview)

        self.process_listbox.pack(fill=tk.BOTH, expand=True)
        self.process_listbox.bind("<Double-Button-1>", self.on_double_click)

    def show_running_processes(self):
        self.process_listbox.delete(0, tk.END)  # Clear the listbox
        for process in psutil.process_iter(['pid', 'name', 'username']):
            try:
                process_info = process.info
                process_name = process_info['name']
                process_pid = process_info['pid']
                process_username = process_info['username']
                self.process_listbox.insert(tk.END, f"PID: {process_pid}, Name: {process_name}, User: {process_username}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def on_double_click(self, event):
        selected_index = self.process_listbox.curselection()
        if selected_index:
            selected_process = self.process_listbox.get(selected_index[0])  # Use index 0 instead of 1
            self.master.entry1.delete(0, tk.END)  # Clear the entry
            selected_name = selected_process.split("Name: ")[1].split(",")[0].strip()
            self.master.entry1.insert(0, selected_name)  # Set the selected process name in the entry
            self.destroy()  # Close the process list window      


if __name__ == "__main__":
    app = App()
    app.mainloop()