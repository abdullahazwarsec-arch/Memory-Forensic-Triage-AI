import pandas as pd
import shap
import joblib
import matplotlib.pyplot as plt

# 1. Load the saved AI Brain
print("Loading saved AI model...")
model = joblib.load("random_forest_model.pkl")

# 2. Load the dataset
print("Loading dataset for explanation...")
df = pd.read_csv("Obfuscated-MalMem2022.csv")
df['Class'] = df['Class'].apply(lambda x: 0 if x == 'Benign' else 1)
if 'Category' in df.columns:
    df = df.drop(columns=['Category'])

X = df.drop(columns=['Class'])

# We only need a small sample of data to generate the plot (100 rows is fast and effective)
X_sample = X.sample(100, random_state=42)

# 3. Create the SHAP Explainer
print("Interrogating the AI with SHAP...")
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X_sample)

# Random Forest binary classifiers output two sets of explanations (Safe vs Malware).
# We want to explain the 'Malware' class (Class 1)
if isinstance(shap_values, list):
    malware_explanations = shap_values[1]
elif len(shap_values.shape) == 3:
    malware_explanations = shap_values[:, :, 1]
else:
    malware_explanations = shap_values

# 4. Generate and save the Summary Plot
print("Creating visual explanation plot...")
plt.figure(figsize=(10, 6))
shap.summary_plot(malware_explanations, X_sample, show=False)

plt.savefig("shap_summary.png", bbox_inches='tight', dpi=300)
print("✅ Explainable AI plot saved successfully as 'shap_summary.png'!")