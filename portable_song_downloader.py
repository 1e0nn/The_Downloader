import json
from pydeezer import Deezer
from pydeezer import Downloader
from pydeezer.constants import track_formats
from datetime import datetime as C,timedelta as G
import shutil
import subprocess
import sys
import yt_dlp
import getpass
import difflib
import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from time import sleep
import whisper
import warnings
import random
from getpass import getuser
import requests
from io import StringIO
import unicodedata
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from tkinter import Text
from PIL import Image, ImageTk  # Nécessaire pour redimensionner l'image
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# Fonction pour déverrouiller le programme et afficher les éléments
def unlock_program():
    # Suppression du champ mot de passe et du bouton de déverrouillage
    try:
        for widget in root.grid_slaves():
            if widget != settings_button:
                widget.grid_forget()
    except:
        pass
    
    if main_dir and (all(key in clechiffre for key in ['email_dz', 'password_dz', 'playlist_id_deezer']) or all(key in clechiffre for key in ['client_id_sc', 'auth_token_sc', 'soundcloud_link']) or 'playlist_yt' in clechiffre):
        label_message.config(text="", fg="white")
        root.geometry("850x300")
        root.deiconify()
        # Affichage des autres éléments
        #print(clechiffre)

        #véirifer sir les champs existes 
        if all(key in clechiffre for key in ['email_dz', 'password_dz', 'playlist_id_deezer']):
            unlocked["session"] = True
            checkbox1.grid(row=0, column=0, padx=20, pady=10, sticky="w")

        if all(key in clechiffre for key in ['client_id_sc', 'auth_token_sc', 'soundcloud_link']):
            unlocked["session"] = True
            checkbox2.grid(row=1, column=0, padx=20, pady=10, sticky="w")

        if 'playlist_yt' in clechiffre:
            checkbox3.grid(row=2, column=0, padx=20, pady=10, sticky="w")

        if all(key in clechiffre for key in ['email_dz', 'password_dz', 'playlist_id_deezer']) or all(key in clechiffre for key in ['client_id_sc', 'auth_token_sc', 'soundcloud_link']) or 'playlist_yt' in clechiffre:
            button_start.grid(row=3, column=0, padx=20, pady=15, sticky="ew")
            label_message.grid(row=4, column=0, padx=20, pady=10, sticky="ew")
            frame_download_info.grid(row=5, column=0, padx=100, pady=15, sticky="nsew")
    else:
        root.iconify()
        label_message.config(text="Attente de configuration des paramètres.", fg="white")
        label_message.grid(row=4, column=0, padx=20, pady=10, sticky="ew")

# Fonction pour afficher la fenêtre de paramètres
def open_settings():
    global main_dir
    # Fenêtre pour changer les paramètres
    settings_window = tk.Toplevel(root)
    settings_window.title("Paramètres")
    settings_window.geometry("400x400")
    settings_window.configure(bg="#2f2f2f")

    # Fonction pour mettre à jour les messages d'erreur
    def update_error_labels(champ_a_remplir):
        error_mail_deezer.grid_forget()
        error_password_deezer.grid_forget()
        error_playlist_id_deezer.grid_forget()
        error_mail_soundcloud.grid_forget()
        error_password_soundcloud.grid_forget()
        error_path.grid_forget()
        error_soundcloud_link.grid_forget()
        error_yt_link.grid_forget()

        for champ in champ_a_remplir:
            if champ == "path":
                error_path.grid(row=15, column=1, pady=5, sticky="w")
            if champ == "all":
                error_mail_deezer.grid(row=1, column=1, pady=5, sticky="w")
                error_password_deezer.grid(row=3, column=1, pady=5, sticky="w")
                error_playlist_id_deezer.grid(row=5, column=1, pady=5, sticky="w")
                error_mail_soundcloud.grid(row=7, column=1, pady=5, sticky="w")
                error_password_soundcloud.grid(row=9, column=1, pady=5, sticky="w")
                error_soundcloud_link.grid(row=11, column=1, pady=5, sticky="w")
                error_yt_link.grid(row=13, column=1, pady=5, sticky="w")
            if champ == "deezer": 
                if entry_mail_deezer.get().strip() == "": error_mail_deezer.grid(row=1, column=1, pady=5, sticky="w")
                if entry_password_deezer.get().strip() == "": error_password_deezer.grid(row=3, column=1, pady=5, sticky="w")
                if entry_playlist_id_deezer.get().strip() == "": error_playlist_id_deezer.grid(row=5, column=1, pady=5, sticky="w")
            if champ == "soundcloud":
                if entry_mail_soundcloud.get().strip() == "": error_mail_soundcloud.grid(row=7, column=1, pady=5, sticky="w")
                if entry_password_soundcloud.get().strip() == "": error_password_soundcloud.grid(row=9, column=1, pady=5, sticky="w")
                if entry_soundcloud_link.get().strip() == "": error_soundcloud_link.grid(row=11, column=1, pady=5, sticky="w")
            if champ == "youtube":
                error_yt_link.grid(row=13, column=1, pady=5, sticky="w")

    # Labels et champs d'entrée pour chaque variable
    tk.Label(settings_window, text="Mail Deezer:", bg="#2f2f2f", fg="white").grid(row=0, column=0, pady=5, sticky="w", padx=10)
    entry_mail_deezer = tk.Entry(settings_window)
    entry_mail_deezer.insert(0, '')
    entry_mail_deezer.grid(row=0, column=1, pady=5, sticky="ew", padx=10)

    error_mail_deezer = tk.Label(settings_window, text="Ce champ est requis", bg="#2f2f2f", fg="red")

    tk.Label(settings_window, text="Mot de passe Deezer:", bg="#2f2f2f", fg="white").grid(row=2, column=0, pady=5, sticky="w", padx=10)
    entry_password_deezer = tk.Entry(settings_window, show="*")
    entry_password_deezer.insert(0, '')
    entry_password_deezer.grid(row=2, column=1, pady=5, sticky="ew", padx=10)

    error_password_deezer = tk.Label(settings_window, text="Ce champ est requis", bg="#2f2f2f", fg="red")

    #playlist_id_deezer

    tk.Label(settings_window, text="Playlist ID Deezer:", bg="#2f2f2f", fg="white").grid(row=4, column=0, pady=5, sticky="w", padx=10)
    entry_playlist_id_deezer = tk.Entry(settings_window)
    entry_playlist_id_deezer.insert(0, '')
    entry_playlist_id_deezer.grid(row=4, column=1, pady=5, sticky="ew", padx=10)

    error_playlist_id_deezer = tk.Label(settings_window, text="Ce champ est requis", bg="#2f2f2f", fg="red")

    tk.Label(settings_window, text="Mail SoundCloud:", bg="#2f2f2f", fg="white").grid(row=6, column=0, pady=5, sticky="w", padx=10)
    entry_mail_soundcloud = tk.Entry(settings_window)
    entry_mail_soundcloud.insert(0, '')
    entry_mail_soundcloud.grid(row=6, column=1, pady=5, sticky="ew", padx=10)

    error_mail_soundcloud = tk.Label(settings_window, text="Ce champ est requis", bg="#2f2f2f", fg="red")

    tk.Label(settings_window, text="Mot de passe SoundCloud:", bg="#2f2f2f", fg="white").grid(row=8, column=0, pady=5, sticky="w", padx=10)
    entry_password_soundcloud = tk.Entry(settings_window, show="*")
    entry_password_soundcloud.insert(0, '')
    entry_password_soundcloud.grid(row=8, column=1, pady=5, sticky="ew", padx=10)

    error_password_soundcloud = tk.Label(settings_window, text="Ce champ est requis", bg="#2f2f2f", fg="red")

    #soundcloud playlist link

    tk.Label(settings_window, text="SoundCloud Playlist Link:", bg="#2f2f2f", fg="white").grid(row=10, column=0, pady=5, sticky="w", padx=10)
    entry_soundcloud_link = tk.Entry(settings_window)
    entry_soundcloud_link.insert(0, '')
    entry_soundcloud_link.grid(row=10, column=1, pady=5, sticky="ew", padx=10)

    error_soundcloud_link = tk.Label(settings_window, text="Ce champ est requis", bg="#2f2f2f", fg="red")

    #playlist_yt link

    tk.Label(settings_window, text="YouTube Playlist Link:", bg="#2f2f2f", fg="white").grid(row=12, column=0, pady=5, sticky="w", padx=10)
    entry_yt_link = tk.Entry(settings_window)
    if 'youtube' in data_found_saved:
        entry_yt_link.insert(0, brute_clechiffre['playlist_yt'])
    else:
        entry_yt_link.insert(0, '')
    entry_yt_link.grid(row=12, column=1, pady=5, sticky="ew", padx=10)

    error_yt_link = tk.Label(settings_window, text="Ce champ est requis", bg="#2f2f2f", fg="red")

    tk.Label(settings_window, text="Chemin de téléchargement:", bg="#2f2f2f", fg="white").grid(row=14, column=0, pady=5, sticky="w", padx=10)
    entry_path = tk.Entry(settings_window)
    entry_path.insert(0, main_dir)
    entry_path.grid(row=14, column=1, pady=5, sticky="ew", padx=10)

    error_path = tk.Label(settings_window, text="Ce champ est requis", bg="#2f2f2f", fg="red")


    # Case à cocher pour mettre à jour les données enregistrées
    update_data_var = tk.BooleanVar()
    update_data_checkbox = tk.Checkbutton(settings_window, text="Enregistrer que ce qui a été rentré \n(les anciennes données seront écrasés).", variable=update_data_var, bg="#2f2f2f", fg="white", selectcolor="#2f2f2f")
    update_data_checkbox.grid(row=16, column=0, columnspan=2, pady=5, sticky="w", padx=10)
    #print(update_data_var.get())

    # Bouton pour sauvegarder les changements
    def save_changes():
        global clechiffre,main_dir,if_setting_empty_skip
        mail_deezer = entry_mail_deezer.get().strip()
        password_deezer = entry_password_deezer.get().strip()
        playlist_id_deezer = entry_playlist_id_deezer.get().strip()
        mail_soundcloud = entry_mail_soundcloud.get().strip()
        password_soundcloud = entry_password_soundcloud.get().strip()
        soundcloud_link = entry_soundcloud_link.get().strip()
        yt_link = entry_yt_link.get().strip()
        path = entry_path.get().strip()
        rewrite = update_data_var.get()
        check_password = None
        champ_a_remplir = []
        skip_checking = False

        def password_for_settings():
            password_popup = tk.Toplevel(settings_window)
            password_popup.title("Mot de passe")
            password_popup.geometry("500x150")
            password_popup.configure(bg="#2f2f2f")

            check_password = {"check_password": None}

            def submit_password(rewrite):
                global password
                password = password_entry.get().encode()

                if not any(solution in data_found_saved for solution in ["deezer", "soundcloud"]) and chanp_rempli_need_crypt:
                    check_password["check_password"] = True
                elif not rewrite:
                    check_password["check_password"] = decrypt(password, clechiffre)
                else:
                    check_password["check_password"] = True
                    if password_popup.winfo_exists():
                        password_popup.destroy()
                    return True

                #Si case coché récrire que les data rentrées mais vérifier le mot de passe coreespond bien à celui des données déjà enregistrées
                if not rewrite and any(solutions in data_found_saved for solutions in ["deezer", "soundcloud"]):
                    if not check_password["check_password"]:
                        messagebox.showinfo("Error", "Le mot de passe ne correspond pas à celui des données déja enregistrées.")
                        password_entry.delete(0, tk.END)
                        password = None
                        return False
                    else:
                        if password_popup.winfo_exists():
                            password_popup.destroy()
                        return True
                #en gros réecri toutes les données car consièdere qu'une seul solution de chiffrement existe
                else:
                    if password_popup.winfo_exists():
                        password_popup.destroy()
                    return True
            
            #print(rewrite)
            if not any(solution in data_found_saved for solution in ["deezer", "soundcloud"]) and chanp_rempli_need_crypt:
                tk.Label(password_popup, text="Entrez votre mot de passe afin de chiffrer les données:", bg="#2f2f2f", fg="white").pack(pady=10)
            elif not rewrite:
                tk.Label(password_popup, text="Entrez votre mot de passe afin de vérifier si il corespond aux données déja chiffrés:", bg="#2f2f2f", fg="white").pack(pady=10)
            else:
                tk.Label(password_popup, text="Entrez votre mot de passe afin de chiffrer les données:", bg="#2f2f2f", fg="white").pack(pady=10)
            password_entry = tk.Entry(password_popup, show="*")
            password_entry.pack(pady=5)

            submit_button = ttk.Button(password_popup, text="Valider", command=lambda: submit_password(rewrite))
            submit_button.pack(pady=10)

            password_popup.transient(settings_window)
            password_popup.grab_set()
            settings_window.wait_window(password_popup)
            return check_password["check_password"]

        #CHECKING IF CRYPTED saved data existing
        if 'deezer' in data_found_saved or 'soundcloud' in data_found_saved or 'youtube' in data_found_saved:
            skip_checking = True

        # Validation
        if not path:
            champ_a_remplir.append("path")
            # print("Chemin de téléchargement vide.")            
        
        # Vérifier que les champs ne sont pas tous vides
        if (not mail_deezer and not password_deezer and not playlist_id_deezer) and (not mail_soundcloud and not password_soundcloud and not soundcloud_link) and not yt_link and not skip_checking:
            champ_a_remplir.append("all")
            # print("Tous les champs sont vides.")

        # Vérifier que les champs sont remplis par paire
        if (mail_deezer and not password_deezer) or (password_deezer and not mail_deezer) or (mail_deezer and not playlist_id_deezer) or (playlist_id_deezer and not mail_deezer) or (password_deezer and not playlist_id_deezer) or (playlist_id_deezer and not password_deezer) and not skip_checking:
            champ_a_remplir.append("deezer")
            # print("Champs Deezer incomplets.")
        
        if (mail_soundcloud and not password_soundcloud) or (password_soundcloud and not mail_soundcloud) or (mail_soundcloud and not soundcloud_link) or (soundcloud_link and not mail_soundcloud) and not skip_checking:
            champ_a_remplir.append("soundcloud")
            # print("Champs SoundCloud incomplets.")

        update_error_labels(champ_a_remplir)

        #si les champs sont vides quitte la fonction save car ne doit pas save les données
        if champ_a_remplir:
            return
        
        #données à chiffrer
        encrypted_data = {}

        #champs remplis qui nécessaite un chiffrement
        chanp_rempli_need_crypt = {}

        
        if  mail_deezer and  password_deezer and  playlist_id_deezer:
            chanp_rempli_need_crypt['deezer'] = True
            clechiffre['email_dz'] = mail_deezer
            clechiffre['password_dz'] = password_deezer
            clechiffre['playlist_id_deezer'] = playlist_id_deezer
            encrypted_data['playlist_id_deezer'] = playlist_id_deezer
            brute_clechiffre['playlist_id_deezer'] = playlist_id_deezer


        if  mail_soundcloud and  password_soundcloud and  soundcloud_link:
            chanp_rempli_need_crypt['soundcloud'] = True
            clechiffre['client_id_sc'] = mail_soundcloud
            clechiffre['auth_token_sc'] = password_soundcloud
            clechiffre['soundcloud_link'] = password_soundcloud
            encrypted_data['soundcloud_link'] = soundcloud_link
            brute_clechiffre['soundcloud_link'] = soundcloud_link

        if  yt_link:
            clechiffre['playlist_yt'] = yt_link
            brute_clechiffre['playlist_yt'] = yt_link
            #encrypted_data['playlist_yt'] = yt_link

        # Si tout est valide, fermer la fenêtre et appliquer les changements

        if not os.path.exists(path):
            try:
                os.makedirs(path)
            except:
                log_print(f"Impossible de créer le répertoire: {path}",A,True)
                messagebox.showerror("Erreur", "Impossible de créer le répertoire, veuillez vérifier ce dernier.")
                return
        
        log_print(f"Le dossier de téléchargment a été mis à jour: {os.path.abspath(path)}", F, True)

        main_dir = os.path.abspath(path)

        encrypted_data["download_path"] = main_dir

        if any(key in clechiffre for key in ["email_dz", "password_dz", "client_id_sc", "auth_token_sc"]) and chanp_rempli_need_crypt: # check if any of the keys are in the dictionary
            check_password = password_for_settings()

        for var_name, var_value in clechiffre.copy().items():
            if var_name in ["email_dz", "password_dz", "client_id_sc", "auth_token_sc"] and check_password and chanp_rempli_need_crypt:
                
                try:
                    encryption_key = derive_key_from_password(password)
                    ciphertext, iv , tag = encrypt_message(var_value, encryption_key)
                    log_print(f"Encrypted {var_name} successfully.", F, True)
                except Exception as e:
                    log_print(f"Error while encrypting: {e}", I, True)
                    return False
                
                encrypted_data[var_name] = {
                    "iv": encode_base64(iv),
                    "tag": encode_base64(tag),
                    "ciphertext": encode_base64(ciphertext),
                }

            if var_name == "playlist_yt":
                encrypted_data[var_name] = var_value
                #vérifier si juste playlist_yt dans clechiffre et si mot de passe pour les autres données déja rentée
                #print(unlocked)
                if ("deezer" in data_found_saved or "soundcloud" in data_found_saved) and check_password is None and not unlocked["session"]:
                #     #Si non que YT Si 
                    answer = messagebox.askyesno("Confirmation", "Voulez-vous déchiffrer le reste des données existantes?")
                    if answer:
                        settings_window.destroy()
                        save_encryption_data(data_json, encrypted_data,rewrite)
                        messagebox.showinfo("Succès", "Les paramètres ont été mis à jour.")

                        #taffer le rewrite

                        try:
                            for widget in root.grid_slaves():
                                if widget != settings_button:
                                    widget.grid_forget()
                        except:
                            pass
                        #Entrée pour le mot de passe
                        entry_password = ttk.Entry(root, show="*", font=("Helvetica", 18),)
                        entry_password.grid(row=0, column=0, padx=200, pady=20, sticky="ew")
                        #print(entry_password.get().encode())

                        # Bouton pour déverrouiller les clés de chiffrement
                        button_unlock = ttk.Button(root, text="Déverrouiller", command=lambda: decrypt(entry_password.get().encode()), style="TButton")
                        button_unlock.grid(row=1, column=0, padx=300, pady=10, sticky="ew")

                        return

        settings_window.destroy()
        save_encryption_data(data_json, encrypted_data,rewrite)
        messagebox.showinfo("Succès", "Les paramètres ont été mis à jour.")
        root.deiconify()
        unlock_program()

    save_button = ttk.Button(settings_window, text="Sauvegarder", command=save_changes)
    save_button.grid(row=17, column=0, columnspan=2, pady=10)

    # Assurer que les colonnes et lignes s'étendent
    settings_window.grid_columnconfigure(1, weight=1)
    settings_window.grid_rowconfigure(17, weight=1)

def selection_streaming_source():
    global counter_finish, if_setting_empty_skip

    dl_type = []
    retirer = False
    counter_finish = 0  # Réinitialiser le compteur à 0 au début
    
    if var1.get():
        dl_type.append("deezer")
    if var2.get():
        dl_type.append("soundcloud")
    if var3.get():
        dl_type.append("youtube")

    for i in if_setting_empty_skip:
        if i in dl_type:
            dl_type.remove(i)
            log_print(f"Champs {i} vides.", I, True)
            messagebox.showerror("Erreur", f"Les champs {i} présents dans les settings sont vides.")
            message=f"Veuillez refaire votre sélection sans {i}."
            retirer = True

    if dl_type:
        message = f"Chargement en cours de {', '.join(dl_type)}..."
        # Efface les informations précédentes
        for widget in frame_download_info.winfo_children():
            widget.destroy()

        # Exécuter les tâches de téléchargement dans des threads séparés
        if "deezer" in dl_type:
            threading.Thread(target=download_from_deezer).start()
        if "soundcloud" in dl_type:
            threading.Thread(target=download_from_soundcloud).start()
        if "youtube" in dl_type:
            threading.Thread(target=download_from_youtube).start()

        # Vérifier l'état des téléchargements sans bloquer l'interface
        root.after(100, check_completion, len(dl_type))
    else:
        if not retirer:
            message = "Aucune sélection faite."
    
    label_message.config(text=message, fg="white")
    root.update_idletasks()  # Mise à jour de l'interface graphique

def check_completion(total_tasks): 
    if counter_finish >= total_tasks:
        # Mise à jour de l'interface graphique pour indiquer la fin du chargement
        label_message.config(text="Chargement terminé.", fg="white")
        root.update_idletasks()
    else:
        # Re-vérifier après 100ms si tous les téléchargements ne sont pas encore terminés
        root.after(100, check_completion, total_tasks)


def download_from_deezer():
    global arl
    global deezer
    global counter_finish

    if not arl:
        arl = login_deezer(clechiffre['email_dz'], clechiffre['password_dz'])
    elif arl == "error":
        return
    
    deezer = Deezer(arl=arl)
    aldl_deezer, already_dl_dico = retrieve_id_and_title(clechiffre['playlist_id_deezer'])
    download_tracks(sng_ids)

    # Incrémenter le compteur une fois terminé
    with counter_lock:
        counter_finish += 1


def download_from_soundcloud():
    global counter_finish
    # Simuler le téléchargement SoundCloud
    client_id = clechiffre['client_id_sc']
    auth_token = clechiffre['auth_token_sc']
    downloaded_tracks, aldl_sc = run_soundcloud_command(clechiffre["soundcloud_link"], client_id, auth_token, main_dir)

    # Incrémenter le compteur une fois terminé
    with counter_lock:
        counter_finish += 1


def download_from_youtube():
    global counter_finish
    try:
        sng_ids_yt, to_dl_yt, name_ids_yt, aldl_yt = list_songs_in_playlist(clechiffre["playlist_yt"])
    except:
        return
    
    if sng_ids_yt:
        dl(sng_ids_yt, to_dl_yt)
        log_print(f"{len(sng_ids_yt)} tracks downloaded.", F, True)
        log_print(f"Downloaded Tracks: \n{name_ids_yt}", F, True)
        if len(sng_ids_yt) == 1:
            display_download_info(f"{len(sng_ids_yt)} musique téléchargée depuis youtube:", name_ids_yt)
        else:
            display_download_info(f"{len(sng_ids_yt)} musiques téléchargées depuis youtube:", name_ids_yt)
    else:
        log_print("No tracks downloaded.", I, True)
        display_download_info("Aucune nouvelle musique à télécharger depuis youtube.", '')

    # Incrémenter le compteur une fois terminé
    with counter_lock:
        counter_finish += 1


# Fonction pour afficher les informations de téléchargement
def display_download_info(song_count_message, song_list):
    root.geometry("850x800")
    # Créer un label pour afficher le nombre de chansons téléchargées
    label_song_count = tk.Label(frame_download_info, text=song_count_message, fg="white", bg="#2f2f2f", font=("Helvetica", 16, "bold"))
    label_song_count.pack(pady=5)

    # Créer un widget Text pour afficher la liste des chansons à télécharger
    text_song_list = Text(frame_download_info, height=5, bg="#3a3a3a", fg="white", font=("Helvetica", 13), wrap=tk.WORD, borderwidth=1)
    if song_list:
        for song in song_list:
            text_song_list.insert(tk.END, f"- {song}\n")
        text_song_list.pack(pady=5)

#déchiffrement des données de connexion

def decode_base64(encoded_data):
    return base64.b64decode(encoded_data.encode())

def decrypt_message(ciphertext, aes_key, iv, tag):
    #print("\x1b[93m[-] Decrypting identifiers...\x1b[0m")
    try:
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        #log_print("Fichier déchiffré avec succès.",F,True)
        return decrypted_data.decode()
    except Exception as e:
        log_print(f"Fichier pas déchiffré:{e}",A,True)
        return False

def decrypt(password=None,clechiffre_from_settings=None):
    
    #print(password)

    if not password:
        password = entry_password.get().encode()

    #print(password)
    log_print("Decrypting identifiers...", I, True)
    #password = input("\n\x1b[93mEnter your password: \x1b[0m").encode()

    #loaded_dencrypted_data = json.load(dechiffre(password,data_json))

    with open(data_json, 'r') as file:
        loaded_encrypted_data = json.load(file)

    for var_name, data in loaded_encrypted_data.items():
        #vérifie si data a bien une longueur de 4
        if len(data) != 3:
            # print(len(data))
            # print(data)
            if clechiffre_from_settings and var_name in clechiffre_from_settings:
                pass
            else:
                clechiffre[var_name] = data
        else:           
            #print(clechiffre)  
            #exit()
            # loaded_nonce = decode_base64(data["nonce"])
            #loaded_salt = decode_base64(data["salt"])
            loaded_iv = decode_base64(data["iv"])
            loaded_tag = decode_base64(data["tag"])
            loaded_ciphertext = decode_base64(data["ciphertext"])

            try:
                # decryption_key = derive_key_from_password(password, loaded_salt)
                # decrypted_message = decrypt_message(loaded_nonce, loaded_ciphertext, loaded_tag, decryption_key)
                decryption_key = derive_key_from_password(password)
                decrypted_message = decrypt_message(loaded_ciphertext, decryption_key, loaded_iv, loaded_tag)

            except Exception as e:
                log_print(f"Error while decrypting: {e}", I, True)
                log_print("Incorrect password!", I, True)
                entry_password.delete(0, tk.END)
                return False

            if decrypted_message:
                if clechiffre_from_settings and var_name in clechiffre_from_settings:
                    pass
                else:   
                    clechiffre[var_name] = decrypted_message
            else:
                if not clechiffre_from_settings:
                    messagebox.showerror("Erreur", "Mot de passe incorrect!")
                log_print("Incorrect password!", I, True)
                entry_password.delete(0, tk.END)
                return False
    
    if clechiffre:
        log_print("Decryption process completed.", F, True)
        unlock_program()
        #print(keys_var)
        #print(clechiffre)
        return clechiffre
    else:
        log_print("No data decrypted.", I, False)
        messagebox.showerror("Erreur", "Mot de passe incorrect!")
        entry_password.delete(0, tk.END)
        return False

def encode_base64(data):
    return base64.b64encode(data).decode()

def derive_key_from_password(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'\xf4\xad\x17\xc0\x90\x81\xf9oLj\x0e}\n\xed=\x81',
        iterations=1000000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_message(message, key):
    try:
        iv = os.urandom(12)  # Recommandé : 12 octets pour GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        return ciphertext, iv, encryptor.tag  # Retourne aussi le Tag
    
    except Exception as e:
        log_print(f"Échec du chiffrement de la clé AES : {e}",A,True)

def save_encryption_data(file_path, encrypted_data,rewrite=False):
    if os.path.exists(file_path) and not rewrite:
        with open(file_path, 'r') as file:
            existing_data = json.load(file)
        existing_data.update(encrypted_data)
        with open(file_path, 'w') as file:
            json.dump(existing_data, file)
        # print(existing_data)
        log_print(f"Data updated to the file: {file_path}", F, True)
    else:
        with open(file_path, 'w') as file:
            json.dump(encrypted_data, file)
        log_print(f"Data saved to the file: {file_path}", F, True)

# Fonction pour vérifier si le répertoire existe, sinon le créer
def check_directory(path):
    if not os.path.exists(path):
        try:
            os.makedirs(path)
            print(f"\x1b[92m[+] Répertoires crée car il n'a pas été trouvé {path}.\x1b[0m")
            return True
        except OSError as e:
            print(f"\x1b[91m[!] Erreur lors de la création du répertoire {path}: \n{e}\x1b[0m")
            return False
    return True

def log_print(message, log_code='', print_message=False):
    log_path2=f'C:\\Users\\{getpass.getuser()}\\Downloads\\.backup_dl\\main_log.txt'
    log_path = os.path.join(os.path.dirname((__file__)), '.conf\\main_log.txt')

    M=message;LC=log_code;R='\x1b[0m';CO={F:'\x1b[92m',I:'\x1b[93m',A:'\x1b[91m'};P=print
    try:
        with open(log_path,'a',  encoding='utf-8') as file1, open(log_path2, 'a',  encoding='utf-8') as file2:
            G=C.now().strftime('%Y-%m-%d %H:%M:%S');J=CO.get(LC,'')
            if LC:LC=f"[{LC}] "
            K=f"{G} - {LC}{M}\n";file1.write(K);file2.write(K)
            if print_message:P(f"{J}{LC}{M}{R}")
    except Exception as L:P(f"Erreur lors de la création des fichiers de log : {L}")


def update_json_file(ids,mode):

    downloaded_ids = {"youtube": [], "deezer": []}

    # Charger le fichier JSON s'il existe déjà
    if os.path.exists(downloaded_ids_log_file):
        with open(downloaded_ids_log_file, 'r') as json_file:
            downloaded_ids = json.load(json_file)
    # Ajouter les nouveaux IDs
    downloaded_ids[mode].extend(ids)

    # Enregistrer le fichier JSON mis à jour
    with open(downloaded_ids_log_file, 'w') as json_file:
        json.dump(downloaded_ids, json_file, indent=2)

def check_internet_connection():
    try:
        #requests.get("https://www.google.com", timeout=2)
        subprocess.check_output(["ping", "-n", "1", "8.8.8.8"])
        print("\x1b[92m[+] Connexion internet détectée.\x1b[0m")  
    except subprocess.CalledProcessError:
        print("\x1b[91m[!] Aucune connexion internet détectée!\x1b[0m")
        messagebox.showerror("Erreur", "Aucune connexion internet détecté!")
        sys.exit(1)

def find_main_dir():
    global brute_clechiffre

    #trouver le chemin du script
    script_path = os.path.dirname((__file__))
    conf_folder = os.path.join(script_path,".conf")
    data_json = os.path.join(conf_folder,"data.json")

    #créer le dossier de conf de l'app
    if not os.path.exists(conf_folder):
        os.makedirs(conf_folder)
        os.system(f'attrib +h {conf_folder}')
        # print(f"[+] Hidden folder created at: {conf_folder}")


    # créer le dossier de backup
    back_path = f'C:\\Users\\{getpass.getuser()}\\Downloads\\.backup_dl'
    if not os.path.exists(back_path):
        os.makedirs(back_path)
        os.system(f'attrib +h {back_path}')
        # print(f"[+] Hidden folder created at: {back_path}")

    log_print(f"Folder .conf at :{conf_folder}", F, False)
    log_print(f"Folder .backup_dl at :{back_path}", F, False)

    #ouvrir un fichier data.json et récuérer dans ce fichier json le sc_playlist_name

    if os.path.exists(data_json):
        try:
            if os.stat(data_json).st_size == 0:
                log_print(f"data.json is empty.", I, True)
                return "Aucune donnée enregistré trouvé, veuillez rentrer un chemin de téléchargement ainsi qu'au moin une solution de téléchargement.", data_json, back_path, conf_folder
            else:
                with open(data_json, 'r') as file:
                    brute_clechiffre = json.load(file)
                    if 'download_path' in brute_clechiffre:
                        
                        supposed_main_dir = brute_clechiffre['download_path']
                        if not supposed_main_dir:
                            log_print(f"Download path not found.", I, True)
                            return "No download path found, please choose one in setting.",data_json,back_path,conf_folder  
                        if os.path.exists(supposed_main_dir):
                            main_dir = supposed_main_dir
                            log_print(f"Download path found: {main_dir}", F, True)
                        else:
                            supposed_main_dir = supposed_main_dir.replace(supposed_main_dir[:2], os.path.splitdrive(script_path)[0])
                            if os.path.exists(supposed_main_dir):
                                main_dir = supposed_main_dir
                                log_print(f"Download path found in saved '{brute_clechiffre['download_path']}' but not existing instead a similar path existing '{supposed_main_dir}' chosing this path.", F, True)
                            else:
                                log_print(f"The download path saved is not existing.", I, True)
                                answer = messagebox.askyesno("Confirmation", f"The download path saved is not existing:\n'{supposed_main_dir}'\n Do you want to choose a new one ?")
                                if answer:
                                    return  "Please enter a new Path in the settings",data_json,back_path,conf_folder 
                                else:
                                    main_dir = supposed_main_dir
                                    os.mkdir(main_dir)
                            log_print(f"Updated download path: {main_dir}", F, True)
                    else :
                        log_print(f"No download path found", I, True)
                        return  "No download path found, please choose one in setting.",data_json,back_path,conf_folder 

        except Exception as e:
            log_print(f"Error while reading data.json: \n{e}", A, False)
    else:
        log_print(f"Data.json not found.", I, True)
        return "Aucune donnée enregistré trouvé, veuillez rentrer un chemin de téléchargement ainsi qu'au moin une solution de téléchargement.",data_json,back_path,conf_folder 


    return main_dir,data_json,back_path,conf_folder                  



def transcribe(url,model):
    with open('.temp', 'wb') as f:
        f.write(requests.get(url).content)
    result = model.transcribe('.temp')
    return result["text"].strip()

# def click_checkbox(driver):
#     driver.switch_to.default_content()
#     driver.switch_to.frame(driver.find_element(By.XPATH, ".//iframe[@title='reCAPTCHA']"))
#     driver.find_element(By.ID, "recaptcha-anchor-label").click()
#     driver.switch_to.default_content()

def request_audio_version(driver):
    driver.switch_to.default_content()
    driver.switch_to.frame(driver.find_element(By.XPATH, ".//iframe[@title='recaptcha challenge expires in two minutes']"))
    driver.find_element(By.XPATH, '//*[@id="recaptcha-audio-button"]').click()

def solve_audio_captcha(driver,model):
    text = transcribe(driver.find_element(By.ID, "audio-source").get_attribute('src'),model)
    driver.find_element(By.ID, "audio-response").send_keys(text)
    driver.find_element(By.ID, "recaptcha-verify-button").click()

def random_delay():
    # Générer un délai aléatoire entre 1 et 3 secondes
    return random.uniform(1, 3)

def login_deezer(email, password):

    profile_path = f"C:\\Users\\{getuser()}\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 1"

    # Rediriger stdout vers un StringIO

    options = Options()

    # Spécifier le chemin vers le répertoire du profil Chrome
    options.add_argument(f"user-data-dir={profile_path}")

    browser = webdriver.Chrome(options=options)

    # Minimiser la fenêtre
    browser.minimize_window()

    browser.get('https://www.deezer.com/fr/login?')

    def good():
        # Vérifier si le site a été redirigé afin de savoir si l'utilisateur est déjà connecté et ainsi éviter de se reconnecter
        sleep(random_delay())
        if browser.current_url != 'https://www.deezer.com/fr/login?':
            log_print("Le site deezer est déja connecté.", I, False)
            cookies = browser.get_cookies()
            for cookie in cookies:
                if cookie['name'] == 'arl':
                    return cookie['value']
        log_print("Deezer non connecté, le script essaye une autre méthode d'authentification.", I, False)                

    try:
        cookie = good()
        if cookie:
            return cookie
        
        try:
            #  Attendre que l'élément soit visible
            if browser.find_element(By.XPATH, '//*[@id="gdpr-btn-accept-all"]'):
                log_print('Pop-up visible', I, False)
                # Trouver et cliquer sur le bouton 'Accepter' dans la pop-up de confidentialité
                agree_button = browser.find_element(By.XPATH, '//*[@id="gdpr-btn-accept-all"]')
                agree_button.click()
        except:
            log_print('Pop-up non visible', I, False)

        #envoie des données d'authentification
        browser.find_element(By.ID, 'email').send_keys(email)
        browser.find_element(By.ID, 'password').send_keys(password)
        browser.find_element(By.XPATH, '//*[@id="__next"]/div/div[2]/form/div/button').click()

        cookie = good()
        if cookie:
            return cookie
        else:
            #Bypass du captcha
            try:
                if browser.find_element(By.XPATH, ".//iframe[@title='recaptcha challenge expires in two minutes']"):
                    model = whisper.load_model("base")
                    browser.switch_to.default_content()
                    browser.switch_to.frame(browser.find_element(By.XPATH, ".//iframe[@title='recaptcha challenge expires in two minutes']"))
                    log_print("Bypass du captcha deezer en cours...",I,True)
                    # Charger le modèle de transcription
                    sleep(10)
                    request_audio_version(browser)
                    sleep(0.5)
                    solve_audio_captcha(browser,model)
                    log_print('Captcha solved', F, True)
                    sleep(random_delay())
                    cookie = good()
                    if cookie:
                        return cookie
                else:
                    log_print("Aucun captcha trouvé.",I,True)
                    messagebox.showerror("Erreur", f"Error Occurred in deezer login.")
                    return "error"
            except Exception as e:
                log_print(f"Error Occurred in bypassing deezer captcha: \n{e}", A, True)
                return "error"
        
    except Exception as e:
        log_print(f"Error Occurred in deezer login: \n{e}", A, True)
        messagebox.showerror("Erreur", f"Error Occurred in deezer login.")
        return "error"

#deezer retreive playlist
def retrieve_id_and_title(id):  
    print("\n")
    log_print("Downloading from Deezer...", F, True)
    id_to_re_dl_dc = {}
    ti_aldl = []
    sng_ids.clear()
    sng_titles.clear()

    try:
        downloaded_ids = {"youtube": [], "deezer": []}
        # Charger le fichier JSON s'il existe déjà
        if os.path.exists(downloaded_ids_log_file):
            with open(downloaded_ids_log_file, 'r') as json_file:
                downloaded_ids = json.load(json_file)

            already_dl.update(map(str, downloaded_ids["deezer"]))  # Assurez-vous que les éléments sont des chaînes

        # Get the playlist tracks
        track = deezer.get_playlist_tracks(id)

        # Iterate through the list and extract the required information
        for item in track:
            if item['SNG_ID'] in already_dl:
                id_to_re_dl_dc[item['SNG_TITLE']] = item['SNG_ID']
                ti_aldl.append(item['SNG_TITLE'])
                pass
            else:
                sng_ids.append(item['SNG_ID'])
                sng_titles.append(f"{item['SNG_TITLE']} - {item['ART_NAME']}")

        if len(already_dl) > 0:
            log_print(f"{len(already_dl)} tracks skipped because they were already downloaded.", I, True)
            log_print(f"Already Downloaded Tracks: \n{ti_aldl}", I,False)

        if len(sng_ids) > 0:
            log_print(f"{len(sng_ids)} tracks will be downloaded.", I, True)
            # Print the results
            # print("SNG_IDs:", sng_ids)
            # print("SNG_TITLEs:", sng_titles)

        return ti_aldl, id_to_re_dl_dc

    except Exception as e:
        log_print(f"Error Occurred in deezer list songs : \n{e}", A, True)
        messagebox.showerror("Erreur", f"Error Occurred in deezer list songs.")
        return "error"

#deezer download
def download_tracks(list_of_ids):
    try:
        # Rediriger stdout vers un StringIO
        sys.stdout = StringIO()
        
        downloader = Downloader(deezer, list_of_ids, main_dir, quality=track_formats.FLAC, concurrent_downloads=4)
        downloader.start()

        # Récupérer la sortie sous forme de chaîne de caractères
        output = sys.stdout.getvalue()

        # Réinitialiser stdout
        sys.stdout = sys.__stdout__

        # Utiliser une expression régulière pour extraire le nombre de pistes
        matches = re.search(r'Done downloading all (\d+) tracks.', output)

        # Vérifier si une correspondance a été trouvée
        if matches:
            # Extraire le nombre de pistes
            num_tracks = int(matches.group(1))
            if num_tracks != len(list_of_ids):
                log_print(f"Une erreur s'est produite lors du téléchargement de {len(list_of_ids) - num_tracks} pistes.", A, True)
                if num_tracks > 0:
                    log_print(f"Les {len(num_tracks) - list_of_ids} autres pistes ont bien été téléchargées", F, True)
            else:
                log_print(f"Output de deezer: \n{output}\n", I, False)
        else:
            log_print("Aucune correspondance trouvée pour le 'Done downloading all X tracks.' de deezer.", I, True)


        if len(sng_titles) > 0:
            log_print(f"{num_tracks} tracks downloaded. ", F, True)
            log_print(f"Tracks downloaded: \n{sng_titles}\n", F, True)
            # Appeler la fonction pour mettre à jour le fichier JSON avec les IDs téléchargés
            update_json_file(sng_ids, "deezer")
            if num_tracks == 1:
                display_download_info(f"{num_tracks} musique téléchargée depuis deezer:", sng_titles)
            else:
                display_download_info(f"{num_tracks} musiques téléchargées depuis deezer:", sng_titles)

        else:
            log_print(f"No tracks downloaded.\n", I, True)
            display_download_info("Aucune nouvelle musique à télécharger depuis deezer.", '')

    except Exception as e:
        log_print(f"Error Occurred in deezer dl : \n{e}", A, True)
        messagebox.showerror("Erreur", f"Error Occurred in deezer dl.")
        return "error"

#soundcloud download
def run_soundcloud_command(link, client_id, auth_token, download_path):
    log_print("Downloading from SoundCloud...", F, True)

    archive_path = os.path.join(conf_folder, 'archive.txt')

    # Command to execute
    command = [
        'scdl',
        '-l', link,
        '--original-art',
        '--client-id', client_id,
        '--auth-token', auth_token,
        '--path', download_path,
        '-c',
        '--download-archive', archive_path,
        '--no-playlist-folder'
    ]

    # Initialize empty lists
    downloaded_tracks = []
    already_downloaded_tracks = []

    try:
        # Run the command and capture the output
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

        #print(result.stderr)

        # Split the stderr output into lines
        output_lines = result.stderr.splitlines()

        # Create an iterator from the list
        iter_output = iter(output_lines)

        # Iterate through the lines to extract information
        for line in iter_output:
            if "Downloading" in line:
                # Extract track name
                track_name = line.replace("Downloading", "").strip()

                next_line = next(iter_output)

                # Check if the track is already downloaded
                if "already downloaded." in next_line:
                    already_downloaded_tracks.append(track_name)
                elif "is not available in your location..." in next_line:
                    log_print(f"{track_name} is not available in your location.", A, True)
                elif "Downloading the original file." in next_line:
                    # Check the next line after "Downloading the original file."
                    next_line = next(iter_output)
                    if "already downloaded." in next_line:
                        already_downloaded_tracks.append(track_name)
                    elif "Could not get original download link" in next_line:
                        next_line = next(iter_output)
                        if "already downloaded." in next_line:
                            already_downloaded_tracks.append(track_name)
                        else:
                            #print("current line:")
                            #print(line)
                            #print("next line:")
                            #print(next_line)
                            downloaded_tracks.append(track_name)
                    else:
                        downloaded_tracks.append(track_name)
                else:
                    downloaded_tracks.append(track_name)

        if already_downloaded_tracks:
            log_print(f"{len(already_downloaded_tracks)} tracks skipped because they were already downloaded.", I, True)
            log_print(f"Already Downloaded Tracks: \n{already_downloaded_tracks}", I)

        # Print the results
        if downloaded_tracks:
            log_print(f"{len(downloaded_tracks)} tracks downloaded.", F, True)
            log_print(f"Downloaded Tracks: \n{downloaded_tracks}\n", F, True)
            if len(downloaded_tracks) == 1:
                display_download_info(f"{len(downloaded_tracks)} musique téléchargée depuis soundcloud:", downloaded_tracks)
            else:
                display_download_info(f"{len(downloaded_tracks)} musiques téléchargées depuis soundcloud:", downloaded_tracks)
        else:
            log_print("No tracks downloaded.\n", I, True)
            display_download_info("Aucune nouvelle musique à télécharger depuis soundcloud.", '')
    
        return downloaded_tracks, already_downloaded_tracks
    except subprocess.CalledProcessError as e:
        # Handle errors, if any
        log_print(f"Error Occurred in soundcloud: \n{e.stderr}", A, True)
        messagebox.showerror("Erreur", f"Error Occurred in soundcloud.")
        return "error"
    
def list_songs_in_playlist(url):

    already_dl_yt=set()
    to_dl_yt=[]
    sng_ids_yt=[]
    name_ids_yt=[]
    ald_name_yt=[]

    log_print("Downloading from YouTube...", F, True)

    downloaded_ids = {"youtube": [], "deezer": []}
    # Charger le fichier JSON s'il existe déjà
    if os.path.exists(downloaded_ids_log_file):
        with open(downloaded_ids_log_file, 'r') as json_file:
            downloaded_ids = json.load(json_file)

        already_dl_yt.update(map(str, downloaded_ids["youtube"]))  # Assurez-vous que les éléments sont des chaînes

    ydl_opts = {
        'quiet': True,
        'no_warnings': True,
        'ignoreerrors': False,
        'flat_playlist': True,
    }
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info_dict = ydl.extract_info(url, download=False)
            if 'entries' in info_dict:
                for video in info_dict['entries']:
                    if video is not None:
                        #print(f"ID: {video['id']}, Title: {video['title']}, URL: https://www.youtube.com/watch?v={video['id']}")
                        if video['id'] in already_dl_yt:
                            ald_name_yt.append(video['title'])
                            pass
                        else:   
                            sng_ids_yt.append(video['id'])
                            to_dl_yt.append(f"https://www.youtube.com/watch?v={video['id']}")
                            name_ids_yt.append(video['title'])
        
        if already_dl_yt:
            log_print(f'{len(already_dl_yt)} tracks skipped because they were already downloaded.', I, True)
            log_print(f"Already Downloaded Tracks: \n{ald_name_yt}", I)
    
    except subprocess.CalledProcessError as e:
        log_print(f"Error Occurred in youtube list songs: \n{e}",A,True)
        messagebox.showerror("Erreur", f"Error Occurred in youtube list songs.")
        return "error"

    return sng_ids_yt, to_dl_yt, name_ids_yt, ald_name_yt


def dl(sng_ids,url):
    ydl_opts = {
        'format': 'bestaudio/best',  # Choisissez le meilleur format audio/vidéo disponible
        'outtmpl': '{}\\%(title)s.%(ext)s'.format(main_dir.replace(":",":\\")),
        'postprocessors': [
            {
                'key': 'FFmpegExtractAudio',
                'preferredcodec': 'mp3',
                'preferredquality': '0',
            },
            {
                'key': 'FFmpegMetadata',
            },
            {
                'key': 'EmbedThumbnail',  # Ajouter la pochette d'album
                'already_have_thumbnail': False,  # Ne téléchargez pas la pochette d'album si elle est déjà présente
            }
        ],
        'writethumbnail': True,  # Écrire la miniature dans le fichier vidéo
        'prefer_ffmpeg': True,  # Préférez FFmpeg sur avconv pour l'extraction audio
        'quiet': True,  # Ne pas imprimer dans stdout
        'no_warnings': True,  # Ne pas imprimer les avertissements
        'ignoreerrors': False,  # Continuer sur les erreurs de téléchargement
        'restrictfilenames': False,  # Restreindre les noms de fichiers à seulement un ensemble de caractères sûrs
        'nooverwrites': True,  # Ne pas écraser les fichiers
        'writesubtitles': False,  # Écrire les sous-titres dans le fichier vidéo
    }
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            error_code = ydl.download(url)
            update_json_file(sng_ids,"youtube")
    except subprocess.CalledProcessError as e:
        log_print(f"Error Occurred in youtube dl: \n{e}",A,True)
        messagebox.showerror("Erreur", f"Error Occurred in youtube dl.")
        return "error"

# Fonction pour normaliser les chaînes
def normalize_string(s):
    # Décoder les séquences Unicode
    s = s.encode('latin1').decode('unicode-escape')
    # Normaliser les caractères Unicode en forme de composition canonique
    return unicodedata.normalize('NFC', s)

def count_missing_characters(phrase1, phrase2):
    # Generate a list of differences between the two phrases
    diff = difflib.ndiff(phrase1, phrase2)
    
    # Count the number of characters marked as missing (-)
    missing_count = sum(1 for char in diff if char.startswith('- '))
    
    return missing_count

def enlever_accents(texte):
    # Normalisation de la chaîne de caractères pour séparer les accents des lettres de base
    texte_normalise = unicodedata.normalize('NFD', texte)
    # Filtrage pour supprimer les accents
    texte_sans_accents = ''.join(c for c in texte_normalise if unicodedata.category(c) != 'Mn')
    return texte_sans_accents

def checking_missing_filees(list_of_deezer, list_of_sc, list_of_yt, type_dl):
    
    if input("\n Do you want to check if there is some missing files ? (y/n) : ").lower() in ['y','yes','o','oui']:
        log_print("Checking missing files...", F, True)
        normalized_list_of_sc = [normalize_string(s) for s in list_of_sc]
        list_of_aldl = list(set(list_of_deezer + normalized_list_of_sc + list_of_yt))

        log_print(f"{len(list_of_aldl)} tracks suposed to be already downloaded.", I, True)
        #log_print(f"Les musiques déja téléchargés: \n{list_of_aldl}", I, True)
        list_of_files = os.listdir(main_dir)

        #remove lrc files in the directory and list_of_files
        lrc_count = 0
        for file in list_of_files:
            if file.endswith(".lrc"):
                lrc_count += 1
                log_print(f"Removing {file} cause its not a song but a LRC file.", I, False)
                os.remove(os.path.join(main_dir, file))
                list_of_files.remove(file)
            # replace .mp3 .flac .wav .m4a by ''
            if file.endswith(".mp3") or file.endswith(".flac") or file.endswith(".wav") or file.endswith(".m4a") or file.startswith("to_dl_"):
                list_of_files[list_of_files.index(file)] = file.replace(".mp3", "").replace(".flac", "").replace(".wav", "").replace(".m4a", "").replace("to_dl_", "")

        if lrc_count > 0:
            log_print(f"{lrc_count} LRC files removed from the directory.", I, True)

        log_print(f"{len(list_of_files)-1} files found in the directory.", I, True)
        log_print(f"Files in the directory: \n{list_of_files}\n", I, True)
        
        #deezer
        missing_deezer = []
        if list_of_deezer and list_of_files and "deezer" in type_dl:
            id_to_re_dl = []
            for file in list_of_deezer:
                found_deezer = False
                if file not in list_of_files:
                    #print(file)
                    for file2 in list_of_files:
                        if file2.startswith(file):
                            #log_print(f"Found file: {file2}", I, True)
                            #index de file
                            found_deezer = True
                            break
                        elif file2.startswith(enlever_accents(file)):
                            found_deezer = True
                            break
                    #print(found_deezer)
                    if found_deezer == False:
                        log_print(f"Missing file from deezer: {file}", A, True)
                        id_to_re_dl.append(already_dl_dico[file])
                        missing_deezer.append(file)
            if missing_deezer:
                log_print(f"{len(missing_deezer)} deezer songs missing in the directory.\n", I, True)
                if input("Would you like to re-download the missing songs ? (y/n) : ") in ['y','yes','o','oui']:
                    log_print("Re-downloading missing songs from deezer...", F, True)
                    download_tracks(id_to_re_dl)

                #log_print(f"Missing songs: \n{missing_deezer}\n", I, True)
            else:
                log_print("No missing songs for deezer.\n", F, True)

        #soundcloud
        missing_sc = []
        if list_of_sc and list_of_files and "soundcloud" in type_dl:
            for file in normalized_list_of_sc:
                if file not in list_of_files: 
                    found = False
                    for file2 in list_of_files:
                        
                        if count_missing_characters(file, file2) <= 4:
                            log_print(f"Found file: {file2} only {count_missing_characters(file, file2)} characters missing between {file} and {file2}", I, False)
                            found = True
                            break
                    if not found:
                        log_print(f"Missing file from soundcloud: {file}", A, True)
                        #print(f"Missing file  {file}")
                        missing_sc.append(file)
            if missing_sc:
                log_print(f"{len(missing_sc)} soundcloud songs missing in the directory.\n", I, True)
                #log_print(f"Missing songs: \n{missing_sc}", I, True)
                #print(f"Missing songs: \n{missing_sc}\n")
            else:
                log_print("No missing songs for soundcloud.\n", F, True)
        
        #youtube
        missing_yt = []
        if list_of_yt and list_of_files and "youtube" in type_dl:
            for file in list_of_yt:
                if file not in list_of_files:
                    log_print(f"Missing file from youtube: {file}", A, True)
                    missing_yt.append(file)
            if missing_yt:
                log_print(f"{len(missing_yt)} youtube songs missing in the directory.\n", I, True)
                #log_print(f"Missing songs: \n{missing_yt}", I, True)
            else:
                log_print("No missing songs for youtube.\n", F, True)

    else:
        return

if __name__ == '__main__':

    # Configure logging
    F,A,I='+','!','-'

    # Désactiver les avertissements
    warnings.filterwarnings("ignore")

    # Vérifier la connexion internet
    check_internet_connection()
 
    # Variables globales
    clechiffre = {} #client_id_sc,auth_token_sc,email_dz,password_dz...
    brute_clechiffre = {}
    aldl_sc = []
    aldl_yt = []
    sng_ids = []
    sng_titles = []
    already_dl = set()
    already_dl_dico = {}
    aldl_deezer=[]
    arl = ""
    if_setting_empty_skip= []
    unlocked = {"session":False}

    # Variable pour compter le nombre de fonction de téléchargements terminés
    counter_finish = 0
    counter_lock = threading.Lock()  # Verrou pour protéger le compteur de threads

    # Variables pour les chemins des répertoires
    supposed_main_dir,data_json,back_path,conf_folder = find_main_dir()
    downloaded_ids_log_file = os.path.join(conf_folder, 'downloaded_ids.json')

    # Création de la fenêtre principale
    root = tk.Tk()

    # Liste pour les données trouvées dans data.json
    data_found_saved = []

    # Vérifier si les données de connexion chiffrées nécessaires aux solutions de téléchargement sont bien enrégistrées dans data.json
    if all(key in brute_clechiffre for key in ['email_dz', 'password_dz', 'playlist_id_deezer']):
        data_found_saved.append('deezer')
    if all(key in brute_clechiffre for key in ['client_id_sc', 'auth_token_sc', 'soundcloud_link']):
        data_found_saved.append('soundcloud')
    if all(key in brute_clechiffre for key in ['playlist_yt']):
        data_found_saved.append('youtube')

    log_print(f"DL solutions found in data.json: {data_found_saved}", F, True)

    #Si data.json vide message
    if not brute_clechiffre :
        root.iconify()
        messagebox.showinfo("Information", supposed_main_dir)
        main_dir=""
        open_settings()
    #Si juste path go setting avec message
    elif len(brute_clechiffre) == 1 and "download_path" in brute_clechiffre:
        if not os.path.exists(supposed_main_dir):
            root.iconify()
            main_dir=""
            open_settings()
            messagebox.showinfo("Information", "data.json hasn't any download solutions saved please enter at least one download solution.")
        else:
            main_dir = supposed_main_dir
            root.iconify()
            open_settings()
            messagebox.showinfo("Information", "data.json hasn't any download solutions saved please enter at least one download solution.")
    #Si juste pas de path go settings
    elif not os.path.exists(supposed_main_dir):
        main_dir=""
        root.iconify()
        open_settings()
        messagebox.showinfo("Information", supposed_main_dir)
    #Si tout est ok
    else:
        main_dir = supposed_main_dir

    root.title("Musique Downloader")
    root.geometry("850x200")
    root.configure(bg="#2f2f2f")  # Fond gris foncé

    # Style pour les boutons ttk
    style = ttk.Style()
    style.theme_use("clam")  # Choix du thème. Vous pouvez essayer "clam", "alt", "default", "classic"
    style.configure("TButton", padding=6, relief="flat", background="#4d4d4d", foreground="white", font=("Helvetica", 10))
    style.map("TButton", background=[('active', '#5a5a5a')], foreground=[('active', 'white')])

    # Télécharger l'icône des paramètres si elle n'existe pas déjà
    if not os.path.exists(os.path.join(conf_folder, "settings.png")):
        
        # Télécharger l'image et l'enregistrer dans conf_folder
        url = "https://cdn-icons-png.flaticon.com/512/503/503849.png"
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            with open(os.path.join(conf_folder, "settings.png"), 'wb') as out_file:
                shutil.copyfileobj(response.raw, out_file)
            log_print("Settings icon downloaded successfully.", F, True)
        else:
            log_print("Failed to download settings icon.", A, True)

    # Redimensionner l'image de l'icône et ajouter un bouton dynamique
    settings_image = Image.open(os.path.join(conf_folder, "settings.png"))
    settings_image = settings_image.resize((30, 30), Image.Resampling.LANCZOS)  # Redimensionner l'image
    settings_icon = ImageTk.PhotoImage(settings_image)

    #Si donnée chiffré message pour déchiffrer
    if any(solutions in data_found_saved for solutions in ["deezer", "soundcloud"]):

        # Entrée pour le mot de passe
        entry_password = ttk.Entry(root, show="*", font=("Helvetica", 18),)
        entry_password.grid(row=0, column=0, padx=200, pady=20, sticky="ew")

        # Bouton pour déverrouiller les clés de chiffrement
        button_unlock = ttk.Button(root, text="Déverrouiller", command=decrypt, style="TButton")
        button_unlock.grid(row=1, column=0, padx=300, pady=10, sticky="ew")

    # Bouton pour l'icône paramètres, positionné dynamiquement
    settings_button = tk.Button(root, image=settings_icon, command=open_settings, bg="#2f2f2f", relief="flat")
    settings_button.grid(row=5, column=1, padx=10, pady=10, sticky="se")  # Placement en mode grille en bas à droite

    # Variables pour les cases à cocher
    var1 = tk.BooleanVar()
    var2 = tk.BooleanVar()
    var3 = tk.BooleanVar()

    # Création des cases à cocher
    checkbox1 = tk.Checkbutton(root, text="Deezer", variable=var1, bg="#2f2f2f", fg="white", selectcolor="#4d4d4d")
    checkbox2 = tk.Checkbutton(root, text="Soundcloud", variable=var2, bg="#2f2f2f", fg="white", selectcolor="#4d4d4d")
    checkbox3 = tk.Checkbutton(root, text="Youtube", variable=var3, bg="#2f2f2f", fg="white", selectcolor="#4d4d4d")

    # Bouton pour lancer le programme (stylisé avec ttk)
    button_start = ttk.Button(root, text="Lancer le programme", command=selection_streaming_source, style="TButton")

    # Label pour afficher le message de sélection
    label_message = tk.Label(root, text="", fg="white", bg="#2f2f2f", font=("Helvetica", 10))

    # Cadre pour organiser les informations de téléchargement
    frame_download_info = tk.Frame(root, bg="#2f2f2f")

    # Configurer les lignes et colonnes pour le redimensionnement
    root.grid_rowconfigure(5, weight=1)
    root.grid_columnconfigure(0, weight=1)

    #Si juste yt unlock le bail
    if data_found_saved == ['youtube']:
        clechiffre["playlist_yt"] = brute_clechiffre["playlist_yt"]
        unlock_program()
        #open_settings()

    #check missing files
    # checking_missing_filees(aldl_deezer, aldl_sc, aldl_yt, dl_type)

    #backup log file to the local storage
    dl_ids_sc_back = os.path.join(conf_folder,"archive.txt")
    if os.path.exists(downloaded_ids_log_file):
        shutil.copyfile(downloaded_ids_log_file, os.path.join(back_path,'downloaded_ids.json'))
    if os.path.exists(dl_ids_sc_back):
        shutil.copyfile(dl_ids_sc_back, os.path.join(back_path,'archive.txt'))

    # Lancement de la boucle principale
    root.mainloop()
