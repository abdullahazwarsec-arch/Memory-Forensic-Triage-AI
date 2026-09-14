from pathlib import Path
import pandas as pd
import random

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_PATH = BASE_DIR / "data" / "Obfuscated-MalMem2022.csv"
OUTPUT_PATH = BASE_DIR / "data" / "apt_zero_day.csv"

print("Generating Stage 2: Full System Compromise (APT Zero-Day)...")

df = pd.read_csv(DATA_PATH)

# 1. Grab a genuine, heavily infected memory profile
infected_sample = df[df['Class'] != 'Benign'].sample(1, random_state=99).copy()

# Helper function to automatically handle Dot vs Underscore column names
def mutate_feature(df_sample, feature_name, amount):
    underscore_name = feature_name.replace('.', '_')
    if feature_name in df_sample.columns:
        df_sample[feature_name] += amount
    elif underscore_name in df_sample.columns:
        df_sample[underscore_name] += amount
    else:
        df_sample[feature_name] = amount  # Fallback if neither exists

# 2. Mutate it so it becomes a true "Zero-Day" (a mathematical pattern the AI has NEVER seen)
mutate_feature(infected_sample, 'malfind.ninjections', random.randint(2, 5))
mutate_feature(infected_sample, 'psxview.not_in_eprocess', random.randint(1, 3))
mutate_feature(infected_sample, 'dlllist.ndlls', random.randint(5, 15))

# 3. Strip the labels so the AI has to blindly guess based purely on behavior
features_to_drop = [col for col in ['Class', 'Category'] if col in infected_sample.columns]
simulated_threat = infected_sample.drop(columns=features_to_drop)

simulated_threat.to_csv(OUTPUT_PATH, index=False)
print(f"✅ New threat profile saved as '{OUTPUT_PATH.name}'!")