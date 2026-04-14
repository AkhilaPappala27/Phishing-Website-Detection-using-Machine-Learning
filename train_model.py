import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report


# Step 1: Load Dataset

df = pd.read_csv("training_dataset.csv")

# Basic info
print("Dataset loaded successfully")
print("Total samples:", df.shape[0])
print("Total features:", df.shape[1])

# Show first 5 rows
print("\nDataset preview:")
print(df.head())

# Check class distribution
print("\nClass Distribution:")
print(df["Result"].value_counts())

# Feature encoding:
# Values -1, 0, 1 represent different conditions depending on the feature.
# Generally, -1 indicates suspicious/phishing behavior, 1 indicates legitimate behavior.

# Check unique values for each column
for col in df.columns:
    print(f"\nFeature: {col}")
    print(df[col].unique())

# Step 2: Data Cleaning

# Check missing values
print("Missing values:")
print(df.isnull().sum())

# Since there are no missing values, no need to handle them

# Remove duplicate rows (if any)
df.drop_duplicates(inplace=True)
# Final dataset shape after cleaning
print("\nAfter cleaning:")
print("Total samples:", df.shape[0])
print("Total features:", df.shape[1])

# Data Summary
print("Summary Statistics:")
print(df.describe())


# Step 3: Train-Test Split

# Remove 'id' and target
X = df.drop(["Result", "id"], axis=1)
y = df["Result"]

# Split the data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print("Training set size:", X_train.shape)
print("Test set size:", X_test.shape)
print("\nTraining target distribution:")
print(y_train.value_counts())
print("\nTest target distribution:")
print(y_test.value_counts())


# Step 4: Model Training

# Initialize model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

# Train model
model.fit(X_train, y_train)
print("Model training completed successfully")
print("Number of features used:", X_train.shape[1])


# Step 5: Model Evaluation

# Predictions
y_pred = model.predict(X_test)

# Metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, pos_label=1)
recall = recall_score(y_test, y_pred, pos_label=1)
f1 = f1_score(y_test, y_pred, pos_label=1)

# Print results
print("Model Evaluation Results:")
print(f"Accuracy  : {accuracy:.2%}")
print(f"Precision : {precision:.2%}")
print(f"Recall    : {recall:.2%}")
print(f"F1 Score  : {f1:.2%}")

# Compute confusion matrix
cm = confusion_matrix(y_test, y_pred)
# Plot
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Phishing (-1)', 'Legitimate (1)'],
            yticklabels=['Phishing (-1)', 'Legitimate (1)'])

plt.title('Confusion Matrix')
plt.xlabel('Predicted Label')
plt.ylabel('Actual Label')
plt.tight_layout()
plt.show()

#  Classification Report
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

import joblib
import pickle

joblib.dump(model, "phishing_model.pkl")
print("Model saved successfully")

with open("columns.pkl", "wb") as f:
    pickle.dump(X.columns, f)

print("Columns saved successfully")