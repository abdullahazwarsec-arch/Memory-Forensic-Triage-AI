from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_PATH = BASE_DIR / "data" / "Obfuscated-MalMem2022.csv"
MODEL_PATH = BASE_DIR / "models" / "random_forest_model.pkl"

# 1. Load and clean the data exactly like we did in the test
print("Loading data...")
df = pd.read_csv(DATA_PATH)
df['Class'] = df['Class'].apply(lambda x: 0 if x == 'Benign' else 1)
if 'Category' in df.columns:
    df = df.drop(columns=['Category'])

# 2. Separate the Clues (X) from the Answers (y)
print("Splitting data into 80% training and 20% testing...")
y = df['Class']
X = df.drop(columns=['Class'])

# Split the flashcards
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42)

# 3. Train the Random Forest AI
print("Training the Random Forest model (this might take 10-30 seconds)...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 4. Give the AI its final exam on the hidden 20%
print("Testing the model...")
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print(f"\n✅ AI Training Complete!")
print(f"🎯 Model Accuracy: {accuracy * 100:.2f}%")

# 5. Save the trained AI brain to a file
joblib.dump(model, MODEL_PATH)
print(f"💾 Model saved successfully as '{MODEL_PATH.name}'")