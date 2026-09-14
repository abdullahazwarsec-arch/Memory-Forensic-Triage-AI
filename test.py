import pandas as pd

print("Step 1: Reading dataset...")
df = pd.read_csv("Obfuscated-MalMem2022.csv")

# 1. Check for missing or broken values
missing = df.isnull().sum().sum()
print(f"Missing values found: {missing}")

# 2. Convert 'Class' text into binary numbers (0 = Benign, 1 = Malware)
print("\nStep 2: Converting text labels to numbers...")
df['Class'] = df['Class'].apply(lambda x: 0 if x == 'Benign' else 1)

# 3. Drop 'Category' column since we only need safe vs. malicious triage
if 'Category' in df.columns:
    df = df.drop(columns=['Category'])

# 4. Verify the distribution
print("\nStep 3: Class balance check:")
print(df['Class'].value_counts())
print("\n0 = Benign (Safe), 1 = Malware (Infected)")