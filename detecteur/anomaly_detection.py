import customtkinter
import os
import joblib
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from scipy.sparse import csr_matrix
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pickle
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from sklearn.model_selection import train_test_split
from PIL import Image
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM

home_text = "Notre application est conçue pour détecter les anomalies dans les logs Apache, offrant ainsi une solution avancée de détection des attaques telles que les attaques par déni de service distribué (DDoS) ou les intrusions malveillantes.\n\n\
Les logs Apache sont des enregistrements détaillés des activités sur un serveur web, comprenant des informations telles que les adresses IP, les horodatages, les requêtes, les statuts, les tailles des fichiers, les référents, les navigateurs utilisés et les pays d'origine. Notre application analyse ces logs pour détecter les schémas et les comportements suspects, permettant ainsi de protéger votre infrastructure contre les cyberattaques.\n\n\
L'application utilise des techniques avancées d'apprentissage automatique pour modéliser les comportements normaux et identifier les anomalies. Elle prépare les données en les encodant, en les vectorisant et en les divisant en ensembles d'entraînement et de validation. Ensuite, elle applique des modèles tels que l'IsolationForest et la OneClassSVM pour calculer les scores d'anomalie et effectuer la détection.\n\n\
Notre application offre également des fonctionnalités flexibles pour ajuster les seuils de détection d'anomalies, ce qui permet de personnaliser les résultats en fonction de vos besoins spécifiques. Vous pouvez maximiser le score F1 global ou privilégier le rappel pour la détection des attaques spécifiques.\n\n\
En utilisant notre application de détection d'anomalies dans les logs Apache, vous pourrez renforcer la sécurité de votre infrastructure en identifiant rapidement les activités suspectes et en prenant les mesures nécessaires pour protéger vos systèmes.\n\n\
N'hésitez pas à essayer notre application et à bénéficier d'une protection avancée contre les attaques et les intrusions dans votre environnement Apache."

predict_text = ""
predict_text_danger = ""
predict_text_suspect = ""
predict_text_normal = ""

class ToplevelWindowSuspect(customtkinter.CTkToplevel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.geometry("800x600")
        self.title("suspicious anomalies detected")

        # set grid layout 1x2
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # create home frame
        self.home_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.home_frame.grid_columnconfigure(0, weight=1)
        self.home_frame.grid_rowconfigure(0, weight=1)#

        self.textbox = customtkinter.CTkTextbox(self.home_frame)
        self.textbox.grid(row=0, column=0, padx=(30, 30), pady=(30, 30), sticky="nsew")
        self.textbox.insert("0.0", predict_text_suspect)
        self.textbox.configure(state="disabled")

        self.home_frame.grid(row=0, column=0, sticky="nsew")

        #self.label = customtkinter.CTkLabel(self, text="ToplevelWindow")
        #self.label.pack(padx=20, pady=20)

        

        #self.focus()

        """
        self.textbox_predict = customtkinter.CTkTextbox(self)
        self.textbox_predict.configure(state="disabled")
        self.textbox_predict.pack(padx=20, pady=20, fill="both", expand=True)  # Fill the entire frame
        self.textbox_predict.insert("0.0", home_text)
        """


    def set_text(self, text):
        
        self.textbox_predict.delete("0.0", "end")  # Clear existing text
        self.textbox_predict.insert("0.0", text)  # Insert new text
        
        return


class ToplevelWindowDanger(customtkinter.CTkToplevel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.geometry("800x600")
        self.title("dangerous anomalies detected")

        # set grid layout 1x2
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # create home frame
        self.home_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.home_frame.grid_columnconfigure(0, weight=1)
        self.home_frame.grid_rowconfigure(0, weight=1)#

        self.textbox = customtkinter.CTkTextbox(self.home_frame)
        self.textbox.grid(row=0, column=0, padx=(30, 30), pady=(30, 30), sticky="nsew")
        self.textbox.insert("0.0", predict_text_danger)
        self.textbox.configure(state="disabled")

        self.home_frame.grid(row=0, column=0, sticky="nsew")

        #self.label = customtkinter.CTkLabel(self, text="ToplevelWindow")
        #self.label.pack(padx=20, pady=20)

        

        #self.focus()

        """
        self.textbox_predict = customtkinter.CTkTextbox(self)
        self.textbox_predict.configure(state="disabled")
        self.textbox_predict.pack(padx=20, pady=20, fill="both", expand=True)  # Fill the entire frame
        self.textbox_predict.insert("0.0", home_text)
        """


    def set_text(self, text):
        
        self.textbox_predict.delete("0.0", "end")  # Clear existing text
        self.textbox_predict.insert("0.0", text)  # Insert new text
        
        return

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.toplevel_window_suspect = None
        self.toplevel_window_danger = None
        self.change_appearance_mode_event("Dark")
        self.load_model("Isolation Forest")
        self.load_model_training("Isolation Forest")
        self.load_treshold("Best recall")
        self.file_loaded = 0
        self.file_training_loaded = 0
        self.title("Anomaly detection")
        self.geometry("700x450")
        self.danger_treshold = -0.75
        self.suspect_treshold = -0.5

        # set grid layout 1x2
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # load images with light and dark mode image
        image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "images")
        self.logo_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "bug_colored.png")), size=(56, 56))
        self.image_icon_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "bug_dark.png")), size=(20, 20))
        self.home_image = customtkinter.CTkImage(light_image=Image.open(os.path.join(image_path, "info_dark.png")),
                                                 dark_image=Image.open(os.path.join(image_path, "info_white.png")), size=(20, 20))
        self.performance = customtkinter.CTkImage(light_image=Image.open(os.path.join(image_path, "chart_dark.png")),
                                                 dark_image=Image.open(os.path.join(image_path, "chart_white.png")), size=(20, 20))
        self.prediction = customtkinter.CTkImage(light_image=Image.open(os.path.join(image_path, "glass_dark.png")),
                                                     dark_image=Image.open(os.path.join(image_path, "glass_white.png")), size=(20, 20))

        self.entrainement = customtkinter.CTkImage(light_image=Image.open(os.path.join(image_path, "subscript-solid.png")),
                                                     dark_image=Image.open(os.path.join(image_path, "white_.png")), size=(20, 20))

        self.logo_trojan = customtkinter.CTkImage(Image.open(os.path.join(image_path, "logo_trojan.png")), size=(56, 56))
        self.logo_virus = customtkinter.CTkImage(Image.open(os.path.join(image_path, "logo_virus.png")), size=(56, 56))
        self.logo_worms = customtkinter.CTkImage(Image.open(os.path.join(image_path, "logo_worms.png")), size=(56, 56))
        self.logo_spyware = customtkinter.CTkImage(Image.open(os.path.join(image_path, "logo_spyware.png")), size=(56, 56))
        self.logo_downloader = customtkinter.CTkImage(Image.open(os.path.join(image_path, "logo_downloader.png")), size=(56, 56))
        self.logo_dropper = customtkinter.CTkImage(Image.open(os.path.join(image_path, "logo_dropper.png")), size=(56, 56))
        self.logo_backdoor = customtkinter.CTkImage(Image.open(os.path.join(image_path, "logo_backdoor.png")), size=(56, 56))
        self.logo_adware = customtkinter.CTkImage(Image.open(os.path.join(image_path, "logo_adware.png")), size=(56, 56))
        self.logo_anomaly = customtkinter.CTkImage(Image.open(os.path.join(image_path, "warning.png")), size=(56, 56))

        # create navigation frame
        self.navigation_frame = customtkinter.CTkFrame(self, corner_radius=0)
        self.navigation_frame.grid(row=0, column=0, sticky="nsew")
        self.navigation_frame.grid_rowconfigure(5, weight=1)

        self.navigation_frame_label = customtkinter.CTkLabel(self.navigation_frame, text="  Anomaly detection", image=self.logo_anomaly,#image
                                                             compound="left", font=customtkinter.CTkFont(size=15, weight="bold"))
        self.navigation_frame_label.grid(row=0, column=0, padx=20, pady=20)

        self.home_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Informations",
                                                   fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                   image=self.home_image, anchor="w", command=self.home_button_event)
        self.home_button.grid(row=1, column=0, sticky="ew")

        self.train_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Entrainement",
                                                   fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                   image=self.entrainement, anchor="w", command=self.train_button_event)
        self.train_button.grid(row=2, column=0, sticky="ew")

        self.frame_2_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Performance des modèles",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.performance, anchor="w", command=self.frame_2_button_event)
        #self.frame_2_button.grid(row=3, column=0, sticky="ew")

        self.frame_3_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Prédiction",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.prediction, anchor="w", command=self.frame_3_button_event)
        self.frame_3_button.grid(row=4, column=0, sticky="ew")

        self.appearance_mode_menu = customtkinter.CTkOptionMenu(self.navigation_frame, values=["Dark", "Light", "System"],
                                                                command=self.change_appearance_mode_event)
        self.appearance_mode_menu.grid(row=5, column=0, padx=20, pady=20, sticky="s")

        # create home frame
        self.home_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.home_frame.grid_columnconfigure(0, weight=1)
        self.home_frame.grid_rowconfigure(0, weight=1)#

        self.textbox = customtkinter.CTkTextbox(self.home_frame)
        self.textbox.grid(row=0, column=0, padx=(30, 30), pady=(30, 30), sticky="nsew")
        self.textbox.insert("0.0", home_text)
        self.textbox.configure(state="disabled")

        # create second frame
        self.second_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.second_frame.grid_columnconfigure(0, weight=1)
        self.second_frame.grid_rowconfigure(0, weight=1)#

        self.tabview = customtkinter.CTkTabview(master=self.second_frame)
        self.tabview.grid(row=0, column=0, padx=(30, 30), pady=(30, 30), sticky="nsew")

        self.tabview.add("RMC")  # add tab at the end
        self.load_rmc_tab()

        self.tabview.add("SVM")  # add tab at the end
        self.load_svm_tab()

        self.tabview.add("AdaBoost")  # add tab at the end
        self.load_ada_boost_tab()

        self.tabview.add("XGBoost")  # add tab at the end
        self.load_xg_boost_tab()

        self.tabview.add("MLPC")  # add tab at the end
        self.load_mlpc_tab()

        self.tabview.set("RMC")  # set currently visible tab

        # create third frame
        self.third_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.third_frame.grid_columnconfigure(0, weight=1)

        #the four next elements have to be dispached verticlayy uniformément
        self.third_frame.grid_rowconfigure(0, weight=1)
        self.third_frame.grid_rowconfigure(1, weight=1)
        self.third_frame.grid_rowconfigure(2, weight=1)
        self.third_frame.grid_rowconfigure(3, weight=1)
        self.third_frame.grid_rowconfigure(4, weight=1)
        self.third_frame.grid_rowconfigure(5, weight=1)
        self.third_frame.grid_rowconfigure(6, weight=1)
        self.third_frame.grid_rowconfigure(7, weight=1)
        self.third_frame.grid_rowconfigure(8, weight=1)
        self.third_frame.grid_rowconfigure(9, weight=1)
        self.third_frame.grid_rowconfigure(10, weight=1)

        self.third_frame_list_1 = customtkinter.CTkOptionMenu(self.third_frame, values=["Isolation Forest", "One Class Support Vector Machines"],
                                                                command=self.load_model)
        self.third_frame_list_1.grid(row=3, column=0, padx=20, pady=10)

        self.third_frame_list_1 = customtkinter.CTkOptionMenu(self.third_frame, values=["Best recall", "Best macro F1 score"],
                                                                command=self.load_treshold)
        #self.third_frame_list_1.grid(row=4, column=0, padx=20, pady=10)
       
        self.third_frame_button_2 = customtkinter.CTkButton(self.third_frame, 
                                                            text="Charger un fichier",
                                                            command=self.load_file)
        self.third_frame_button_2.grid(row=4, column=0, padx=20, pady=10)
        
        self.third_frame_button_3 = customtkinter.CTkButton(self.third_frame, 
                                                            text="Analyser",
                                                           command=self.predict)
        self.third_frame_button_3.grid(row=9, column=0, padx=20, pady=10)

        self.third_frame_button_4 = customtkinter.CTkLabel(self.third_frame, text="",
                                                           compound="left", 
                                                           text_color="red", 
                                                           font=customtkinter.CTkFont(size=15, weight="bold"))
        

        
        self.third_frame_button_4.grid(row=10, column=0, padx=20, pady=10)

        self.third_frame_button_5 = customtkinter.CTkLabel(self.third_frame, text="",
                                                           compound="left", 
                                                           text_color="red", 
                                                           font=customtkinter.CTkFont(size=15, weight="bold"))
        

        
        self.third_frame_button_5.grid(row=11, column=0, padx=20, pady=10)

        self.danger_treshold_entry = customtkinter.CTkEntry(self.third_frame, placeholder_text="danger treshold")
        self.danger_treshold_entry.grid(row=5, column=0, padx=20, pady=10)

        self.suspect_treshold_entry = customtkinter.CTkEntry(self.third_frame, placeholder_text="suspicious treshold")
        self.suspect_treshold_entry.grid(row=6, column=0, padx=20, pady=10)

        #train frame

        # create third frame
        self.train_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.train_frame.grid_columnconfigure(0, weight=1)
        self.train_frame.grid_rowconfigure(3, weight=1)

        #the four next elements have to be dispached verticlayy uniformément
        self.train_frame.grid_rowconfigure(0, weight=1)
        self.train_frame.grid_rowconfigure(1, weight=1)
        self.train_frame.grid_rowconfigure(2, weight=1)
        self.train_frame.grid_rowconfigure(3, weight=1)
        self.train_frame.grid_rowconfigure(4, weight=1)
        self.train_frame.grid_rowconfigure(5, weight=1)
        self.train_frame.grid_rowconfigure(6, weight=1)
        self.train_frame.grid_rowconfigure(7, weight=1)
        self.train_frame.grid_rowconfigure(8, weight=1)
        self.train_frame.grid_rowconfigure(9, weight=1)

        self.train_frame_button_2 = customtkinter.CTkButton(self.train_frame, 
                                                            text="Charger un fichier",
                                                            command=self.load_file_training)
        self.train_frame_button_2.grid(row=2, column=0, padx=20, pady=10)

        self.train_frame_list_1 = customtkinter.CTkOptionMenu(self.train_frame, values=["Isolation Forest", "One Class Support Vector Machines"],
                                                                command=self.load_model_training)
        self.train_frame_list_1.grid(row=3, column=0, padx=20, pady=10)

        self.train_frame_button_3 = customtkinter.CTkButton(self.train_frame, 
                                                            text="Entrainer",
                                                           command=self.train)
        self.train_frame_button_3.grid(row=4, column=0, padx=20, pady=10)

        
        self.select_frame_by_name("Information")

    def train(self):
        if self.file_training_loaded == 0:
            messagebox.showinfo("Erreur", "Veuillez d'abord choisir un fichier")
            return
        
        self.dataset_train = self.preprocess_train()

        #remove all detected = 1 from X_train
        self.dataset_train = self.dataset_train[self.dataset_train['detected'] != 1]

        #remove all detected = 2 from X_train
        self.dataset_train = self.dataset_train[self.dataset_train['detected'] != 2]

        y_train = self.dataset_train["detected"].copy()
        x_train = self.dataset_train.copy()
        del x_train["detected"]

        y_test = self.dataset_train["detected"].copy()
        x_test = self.dataset_train.copy()
        del x_test["detected"]

        if self.model_training == "Isolation Forest":
            self.model = IsolationForest()
            self.model.fit(x_train)

            # Save the trained Random Forest model
            joblib.dump(self.model, "./model_detection/IF.pkl")
            print("DONE")

            #treshold update
            anomaly_scores = self.model.decision_function(x_test)  # Anomaly scores based on proximity measures
            
            best_macro_f1 = 0
            self.treshold_macro_f1 = 0.5
            """
            for threshold in np.arange(-0.1, 0.1, 0.001):
                y_pred = np.where(anomaly_scores > threshold, 0, 1)
                print("y_test = ")
                print(y_test)
                y_test = pd.factorize(y_test)
                print("y_test = ")
                print(y_test)
                print("y_pred = ")
                print(y_pred)
                macro_f1 = f1_score(y_test, y_pred, average='macro')
                if macro_f1 > best_macro_f1:
                    self.treshold_macro_f1 = macro_f1

            """
            best_recall_1 = 0
            self.treshold_recall = 0.5
            """
            for threshold in np.arange(-0.1, 0.1, 0.001):
                y_pred = np.where(anomaly_scores > threshold, 0, 1)
                y_test = pd.factorize(y_test)
                recall_1 = recall_score(y_test, y_pred, pos_label=1)
                if recall_1 > best_recall_1:
                    self.treshold_recall = recall_1
            
            
            """
        else :
            self.model = OneClassSVM(gamma='auto')
            self.model.fit(x_train)

            # Save the trained Random Forest model
            joblib.dump(self.model, "./model_detection/OCSVM.pkl")
            print("DONE")

            #treshold update
            anomaly_scores = self.model.decision_function(x_test)  # Anomaly scores based on proximity measures
            
            best_macro_f1 = 0
            self.treshold_macro_f1 = 0.5

            """
            for threshold in np.arange(-0.1, 0.1, 0.001):
                y_pred = np.where(anomaly_scores > threshold, 0, 1)
                macro_f1 = f1_score(y_test, y_pred, average='macro')
                if macro_f1 > best_macro_f1:
                    self.treshold_macro_f1 = macro_f1
            """

            best_recall_1 = 0
            self.treshold_recall = 0.5

            """
            for threshold in np.arange(-0.1, 0.1, 0.001):
                y_pred = np.where(anomaly_scores > threshold, 0, 1)
                recall_1 = recall_score(y_test, y_pred, pos_label=1)
                if recall_1 > best_recall_1:
                    self.treshold_recall = recall_1 
            """
            #print("DONE")

    def preprocess_train(self):

        df = self.data_training

        print("df ->")

        print(df)

        csv_train_split_request = pd.DataFrame()

        print(df[0])

        csv_train_split_request["ip"] = df[0]#["ip"]
        csv_train_split_request["datetime"] = df[1]#["datetime"]
        csv_train_split_request["gmt"] = df[2]#["gmt"]
        csv_train_split_request["request"] = df[3].str.split(" ").str[0]#["request"].str.split(" ").str[0]
        csv_train_split_request["content"] = df[3].str.split(" ").str[1]#["request"].str.split(" ").str[1]
        csv_train_split_request["status"] = df[4]#["status"]
        csv_train_split_request["size"] = df[5]#["size"]
        csv_train_split_request["referer"] = df[6]#["referer"]
        csv_train_split_request["browser"] = df[7]#["browser"]
        csv_train_split_request["country"] = df[8]#["country"]
        csv_train_split_request["detected"] = df[9]#["detected"]

        csv_train_labels_encoded = csv_train_split_request.fillna("")

        df_vectorized = pd.DataFrame(columns=["ip", "datetime", "gmt", "request", "status", "size", "referer", "browser", "country", "detected"])

        codes, uniques = pd.factorize(csv_train_labels_encoded["ip"])
        df_vectorized["ip"] = codes

        codes, uniques = pd.factorize(csv_train_labels_encoded["datetime"])
        df_vectorized["datetime"] = codes

        codes, uniques = pd.factorize(csv_train_labels_encoded["gmt"])
        df_vectorized["gmt"] = codes

        codes, uniques = pd.factorize(csv_train_labels_encoded["request"])
        df_vectorized["request"] = codes

        codes, uniques = pd.factorize(csv_train_labels_encoded["content"])
        df_vectorized["content"] = codes

        codes, uniques = pd.factorize(csv_train_split_request["status"].astype(str))
        df_vectorized["status"] = codes

        codes, uniques = pd.factorize(csv_train_split_request["size"].astype(str))
        df_vectorized["size"] = codes

        codes, uniques = pd.factorize(csv_train_labels_encoded["referer"])
        df_vectorized["referer"] = codes

        codes, uniques = pd.factorize(csv_train_labels_encoded["browser"])
        df_vectorized["browser"] = codes

        codes, uniques = pd.factorize(csv_train_labels_encoded["country"])
        df_vectorized["country"] = codes

        df_vectorized["detected"] = csv_train_labels_encoded["detected"]

        return df_vectorized


    def load_model_training(self, value):
        self.model_training = value

    def open_toplevel_danger(self):
        if self.toplevel_window_danger is None or not self.toplevel_window_danger.winfo_exists():
            self.toplevel_window_danger = ToplevelWindowDanger(self)  # create window if its None or destroyed
            self.toplevel_window_danger.attributes("-topmost", True)
        else:
            self.toplevel_window_danger.focus()  # if window exists focus it


    def open_toplevel_suspect(self):
        if self.toplevel_window_suspect is None or not self.toplevel_window_suspect.winfo_exists():
            self.toplevel_window_suspect = ToplevelWindowSuspect(self)  # create window if its None or destroyed
            self.toplevel_window_suspect.attributes("-topmost", True)
        else:
            self.toplevel_window_suspect.focus()  # if window exists focus it


    def load_treshold(self, value):
        if value == "Best recall":
            self.treshold = self.treshold_recall
        else:
            self.treshold = self.treshold_macro_f1
        return

    def load_rmc_tab(self):
        self.tabview_frame_RMC = self.tabview.tab("RMC")

        # Create the table content as a list of lists
        table_data = [
        ["", "precision", "recall", "f1-score", "support"],
        ["0", "0.94", "0.60", "0.73", "226"],
        ["1", "0.99", "1.00", "0.99", "8550"],
        ["accuracy", "0.99", "", "", "8776"],
        ["macro avg", "0.97", "0.80", "0.86", "8776"],
        ["weighted avg", "0.99", "0.99", "0.99", "8776"],
        ]

        """
        table_data = [
            ["", "precision", "recall", "f1-score", "support"],
            ["Adware", "0.90", "0.87", "0.89", "71"],
            ["Backdoor", "0.73", "0.72", "0.73", "203"],
            ["Downloader", "0.78", "0.73", "0.75", "199"],
            ["Dropper", "0.59", "0.70", "0.64", "181"],
            ["Spyware", "0.55", "0.56", "0.55", "162"],
            ["Trojan", "0.55", "0.48", "0.51", "200"],
            ["Virus", "0.79", "0.85", "0.82", "195"],
            ["Worms", "0.71", "0.68", "0.70", "211"],
            ["accuracy", "", "", "0.69", "1422"],
            ["macro avg", "0.70", "0.70", "0.70", "1422"],
            ["weighted avg", "0.69", "0.69", "0.69", "1422"],
        ]
        """

        # Iterate over the table_data and create labels for each cell
        for i, row in enumerate(table_data):
            for j, cell in enumerate(row):
                label = customtkinter.CTkLabel(self.tabview_frame_RMC, text=cell)
                label.grid(row=i, column=j, sticky="nsew")

        # Configure grid weights to make the table expandable
        for i in range(len(table_data)):
            self.tabview_frame_RMC.grid_rowconfigure(i, weight=1)
        for j in range(len(table_data[0])):
            self.tabview_frame_RMC.grid_columnconfigure(j, weight=1)

    def load_svm_tab(self):
        self.tabview_frame_SVM = self.tabview.tab("SVM")

        # Create the table content as a list of lists
        table_data = [
        ["", "precision", "recall", "f1-score", "support"],
        ["0", "1.00", "0.46", "0.63", "226"],
        ["1", "0.99", "1.00", "0.99", "8550"],
        ["accuracy", "0.99", "", "", "8776"],
        ["macro avg", "0.99", "0.73", "0.81", "8776"],
        ["weighted avg", "0.99", "0.99", "0.98", "8776"],
        ]


        # Iterate over the table_data and create labels for each cell
        for i, row in enumerate(table_data):
            for j, cell in enumerate(row):
                label = customtkinter.CTkLabel(self.tabview_frame_SVM, text=cell)
                label.grid(row=i, column=j, sticky="nsew")

        # Configure grid weights to make the table expandable
        for i in range(len(table_data)):
            self.tabview_frame_SVM.grid_rowconfigure(i, weight=1)
        for j in range(len(table_data[0])):
            self.tabview_frame_SVM.grid_columnconfigure(j, weight=1)

    def load_ada_boost_tab(self):
        self.tabview_frame_ada_boost = self.tabview.tab("AdaBoost")

        # Create the table content as a list of lists
        table_data = [
        ["", "precision", "recall", "f1-score", "support"],
        ["0", "0.81", "0.46", "0.58", "226"],
        ["1", "0.99", "1.00", "0.99", "8550"],
        ["accuracy", "0.98", "", "", "8776"],
        ["macro avg", "0.90", "0.73", "0.79", "8776"],
        ["weighted avg", "0.98", "0.98", "0.98", "8776"],
        ]



        # Iterate over the table_data and create labels for each cell
        for i, row in enumerate(table_data):
            for j, cell in enumerate(row):
                label = customtkinter.CTkLabel(self.tabview_frame_ada_boost, text=cell)
                label.grid(row=i, column=j, sticky="nsew")

        # Configure grid weights to make the table expandable
        for i in range(len(table_data)):
            self.tabview_frame_ada_boost.grid_rowconfigure(i, weight=1)
        for j in range(len(table_data[0])):
            self.tabview_frame_ada_boost.grid_columnconfigure(j, weight=1)

    def load_xg_boost_tab(self):
        self.tabview_frame_xg_boost = self.tabview.tab("XGBoost")

        # Create the table content as a list of lists
        table_data = [
        ["", "precision", "recall", "f1-score", "support"],
        ["0", "0.97", "0.64", "0.77", "226"],
        ["1", "0.99", "1.00", "0.99", "8550"],
        ["accuracy", "0.99", "", "", "8776"],
        ["macro avg", "0.98", "0.82", "0.88", "8776"],
        ["weighted avg", "0.99", "0.99", "0.99", "8776"],
        ]


        # Iterate over the table_data and create labels for each cell
        for i, row in enumerate(table_data):
            for j, cell in enumerate(row):
                label = customtkinter.CTkLabel(self.tabview_frame_xg_boost, text=cell)
                label.grid(row=i, column=j, sticky="nsew")

        # Configure grid weights to make the table expandable
        for i in range(len(table_data)):
            self.tabview_frame_xg_boost.grid_rowconfigure(i, weight=1)
        for j in range(len(table_data[0])):
            self.tabview_frame_xg_boost.grid_columnconfigure(j, weight=1)

    def load_mlpc_tab(self):
        self.tabview_frame_mlpc = self.tabview.tab("MLPC")

        # Create the table content as a list of lists
        table_data = [
        ["", "precision", "recall", "f1-score", "support"],
        ["0", "0.90", "0.54", "0.68", "226"],
        ["1", "0.99", "1.00", "0.99", "8550"],
        ["accuracy", "0.99", "", "", "8776"],
        ["macro avg", "0.95", "0.77", "0.84", "8776"],
        ["weighted avg", "0.99", "0.99", "0.99", "8776"],
        ]

        # Iterate over the table_data and create labels for each cell
        for i, row in enumerate(table_data):
            for j, cell in enumerate(row):
                label = customtkinter.CTkLabel(self.tabview_frame_mlpc, text=cell)
                label.grid(row=i, column=j, sticky="nsew")

        # Configure grid weights to make the table expandable
        for i in range(len(table_data)):
            self.tabview_frame_mlpc.grid_rowconfigure(i, weight=1)
        for j in range(len(table_data[0])):
            self.tabview_frame_mlpc.grid_columnconfigure(j, weight=1)

    def load_model(self, type):
        print("choosed : ", type)

        if type=="Isolation Forest":
            # Load the trained Random Forest model
            self.treshold_macro_f1 = -0.06899999999999998
            self.treshold_recall = 0.09900000000000017
            self.model = joblib.load('./model_detection/IF.pkl')
        elif type=="One Class Support Vector Machines":
            #import MLPC model
            self.treshold_macro_f1 = -0.692
            self.treshold_recall = -0.1
            self.model = joblib.load('./model_detection/OCSVM.pkl')
        else:
            print("the model specified is not recognized")
            return

        """
        #import vectorizer
        with open('./model/vectorizer.pkl', 'rb') as file:
            self.vectorizer = pickle.load(file)
        """

    def load_file_training(self):
        root = tk.Tk()
        root.withdraw()  # Cache la fenêtre principale de tkinter
        file_path = filedialog.askopenfilename()
        self.data_training = pd.read_csv(file_path, header=None)
        self.file_training_loaded = 1

    def load_file(self):
        root = tk.Tk()
        root.withdraw()  # Cache la fenêtre principale de tkinter
        file_path = filedialog.askopenfilename()
        self.data = pd.read_csv(file_path, header=None)
        self.file_loaded = 1

    def preprocess(self):

        df = self.data

        csv_train_split_request = pd.DataFrame()

        print(df[0])

        csv_train_split_request["ip"] = df[0]#["ip"]
        csv_train_split_request["datetime"] = df[1]#["datetime"]
        csv_train_split_request["gmt"] = df[2]#["gmt"]
        csv_train_split_request["request"] = df[3].str.split(" ").str[0]#["request"].str.split(" ").str[0]
        csv_train_split_request["content"] = df[3].str.split(" ").str[1]#["request"].str.split(" ").str[1]
        csv_train_split_request["status"] = df[4]#["status"]
        csv_train_split_request["size"] = df[5]#["size"]
        csv_train_split_request["referer"] = df[6]#["referer"]
        csv_train_split_request["browser"] = df[7]#["browser"]
        csv_train_split_request["country"] = df[8]#["country"]

        csv_train_labels_encoded = csv_train_split_request.fillna("")

        df_vectorized = pd.DataFrame(columns=["ip", "datetime", "gmt", "request", "status", "size", "referer", "browser", "country"])

        codes, uniques = pd.factorize(csv_train_labels_encoded["ip"])
        df_vectorized["ip"] = codes

        codes, uniques = pd.factorize(csv_train_labels_encoded["datetime"])
        df_vectorized["datetime"] = codes

        codes, uniques = pd.factorize(csv_train_labels_encoded["gmt"])
        df_vectorized["gmt"] = codes

        codes, uniques = pd.factorize(csv_train_labels_encoded["request"])
        df_vectorized["request"] = codes

        codes, uniques = pd.factorize(csv_train_labels_encoded["content"])
        df_vectorized["content"] = codes

        codes, uniques = pd.factorize(csv_train_split_request["status"].astype(str))
        df_vectorized["status"] = codes

        codes, uniques = pd.factorize(csv_train_split_request["size"].astype(str))
        df_vectorized["size"] = codes

        codes, uniques = pd.factorize(csv_train_labels_encoded["referer"])
        df_vectorized["referer"] = codes

        codes, uniques = pd.factorize(csv_train_labels_encoded["browser"])
        df_vectorized["browser"] = codes

        codes, uniques = pd.factorize(csv_train_labels_encoded["country"])
        df_vectorized["country"] = codes

        return df_vectorized

    """
    def get_treshold(self, anomaly_scores):
        best_threshold = 0
        best_macro_f1 = 0

        for threshold in np.arange(-0.1, 0.1, 0.001):
            y_pred = np.where(anomaly_scores > threshold, 0, 1)
            macro_f1 = f1_score(y_test, y_pred, average='macro')
            if macro_f1 > best_macro_f1:
                best_macro_f1 = macro_f1
                best_threshold = threshold

        print("Best threshold:", best_threshold)
        print("Best macro f1:", best_macro_f1)
        return

    """

    def predict(self):
        if self.file_loaded == 0:
            messagebox.showinfo("Erreur", "Veuillez d'abord choisir un fichier")
            return
        
        if self.danger_treshold_entry.get()!="":
            self.danger_treshold = float(self.danger_treshold_entry.get())
        if self.suspect_treshold_entry.get()!="":
            self.suspect_treshold = float(self.suspect_treshold_entry.get())
        
        self.dataset = self.preprocess()

        print("dataset : ")
        print(self.dataset)

        anomaly_scores = self.model.decision_function(self.dataset)
        #Calcul treshold adapté

        y_pred = np.where(anomaly_scores > self.treshold, 0, 1)

        y_pred_danger = np.where(anomaly_scores > float(self.danger_treshold), 0, 1)
        y_pred_suspect = np.where(anomaly_scores > float(self.suspect_treshold), 0, 1)

        """
        # Conversion des données d'entrée en format numérique
        dataset = self.data.astype(int)

        #prediction
        #X = self.vectorizer.transform(self.data.values[0])
        y_pred = self.model.predict(dataset)
        """
        

        #print(self.dataset.iloc[0])
        #self.open_toplevel()

        global predict_text
        global predict_text_danger
        global predict_text_suspect
        global predict_text_normal

        predict_text = ""

        for i in range(1, y_pred.shape[0]):
            if y_pred[i]==1:
                predict_text += ' '.join(self.data.iloc[i].astype(str).tolist()) + "\n\n"
        
        for i in range(1, y_pred_danger.shape[0]):
            if y_pred_danger[i]==1:
                predict_text_danger += ' '.join(self.data.iloc[i].astype(str).tolist()) + "\n\n"

        for i in range(1, y_pred_suspect.shape[0]):
            if y_pred_suspect[i]==1:
                predict_text_suspect += ' '.join(self.data.iloc[i].astype(str).tolist()) + "\n\n"


        #self.toplevel_window.textbox_predict.configure(state="disabled")
        print(predict_text)
        #self.toplevel_window.set_text(predict_text)
        #(self.toplevel_window).textbox_predict.insert("0.0", predict_text)

        print(str(y_pred))

        isDangerous = 0
        
        if sum(y_pred_danger)>0:
            self.third_frame_button_4.configure(text="      Dangerous anomalies detected", text_color="#1E6AA4", image=self.logo_anomaly)
            self.open_toplevel_danger()
            self.toplevel_window_danger.focus()
            isDangerous = 1
        #else:
            #self.third_frame_button_4.configure(text="No dangerous anomalies detected !", text_color="green", image='')

        if sum(y_pred_suspect)>0:
            if isDangerous==0:
                self.third_frame_button_4.configure(text="      Suspicious anomalies detected", text_color="#1E6AA4", image=self.logo_anomaly)
            #else:
                #self.third_frame_button_4.configure(text="", text_color="#1E6AA4", image="")

            self.open_toplevel_suspect()
            self.toplevel_window_suspect.focus()
        else:
            if isDangerous==0:
                self.third_frame_button_4.configure(text="No Suspicious anomalies detected !", text_color="green", image='')

          
    def select_frame_by_name(self, name):
        # set button color for selected button
        self.home_button.configure(fg_color=("gray75", "gray25") if name == "Informations" else "transparent")
        self.train_button.configure(fg_color=("gray75", "gray25") if name == "Entrainement" else "transparent")
        self.frame_2_button.configure(fg_color=("gray75", "gray25") if name == "performance_du_modèle" else "transparent")
        self.frame_3_button.configure(fg_color=("gray75", "gray25") if name == "Prédiction" else "transparent")

        # show selected frame
        if name == "Informations":
            self.home_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.home_frame.grid_forget()
        if name == "Entrainement":
            self.train_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.train_frame.grid_forget()
        if name == "performance_du_modèle":
            self.second_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.second_frame.grid_forget()
        if name == "Prédiction":
            self.third_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.third_frame.grid_forget()

    def home_button_event(self):
        self.select_frame_by_name("Informations")

    def train_button_event(self):
        self.select_frame_by_name("Entrainement")

    def frame_2_button_event(self):
        self.select_frame_by_name("performance_du_modèle")

    def frame_3_button_event(self):
        self.select_frame_by_name("Prédiction")

    def change_appearance_mode_event(self, new_appearance_mode):
        customtkinter.set_appearance_mode(new_appearance_mode)


if __name__ == "__main__":
    app = App()
    app.mainloop()

