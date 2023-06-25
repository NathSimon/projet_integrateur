# Détection d'anomalies dans les logs Apache

Notre application est conçue pour détecter les anomalies dans les logs Apache, offrant ainsi une solution avancée de détection des attaques telles que les attaques par déni de service distribué (DDoS) ou les intrusions malveillantes.

## Fonctionnalités

- Analyse des logs Apache pour détecter les schémas et les comportements suspects.
- Utilisation de techniques d'apprentissage automatique avancées, notamment l'IsolationForest et la OneClassSVM.
- Préparation des données en encodant et en vectorisant les informations pertinentes.
- Division des données en ensembles d'entraînement et de validation.
- Possibilité d'ajuster les seuils de détection d'anomalies pour des résultats personnalisés.
- Maximisation du score F1 global ou privilège du rappel pour la détection des attaques spécifiques.

## Comment utiliser l'application

1. Importez les logs Apache dans l'application.
2. Lancez l'analyse pour détecter les anomalies.
3. Consultez les résultats et les scores d'anomalie.
4. Utilisez les seuils de détection pour personnaliser les résultats.
5. Prenez les mesures nécessaires pour protéger votre infrastructure contre les attaques détectées.

## Installation

1. Clonez le dépôt GitHub de l'application.
2. Installez les dépendances requises à l'aide de pip install -r requirements.txt.
3. Exécutez l'application à l'aide de la commande python app.py.

## Exigences système

- Python 3.6 ou une version ultérieure.
- Système d'exploitation compatible (Windows, macOS, Linux).

## Avertissement

Veuillez noter que l'efficacité de la détection d'anomalies dépend de la qualité des logs Apache fournis et de la configuration des seuils de détection. Il est recommandé de suivre les instructions du guide de l'utilisateur pour des résultats optimaux.

---

En utilisant notre application de détection d'anomalies dans les logs Apache, vous pourrez renforcer la sécurité de votre infrastructure en identifiant rapidement les activités suspectes et en prenant les mesures nécessaires pour protéger vos systèmes.

N'hésitez pas à essayer notre application et à bénéficier d'une protection avancée contre les attaques et les intrusions dans votre environnement Apache.
