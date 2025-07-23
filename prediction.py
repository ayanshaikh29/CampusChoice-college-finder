import pandas as pd
import numpy as np
from sklearn import linear_model


str1 = ["COEP", "COEP"]
str2 = ["Computer", "Computer"]
str3 = ["OBC", "OBC"]
str4 = [2022, 2023]  # Use integers, not strings
str5 = [99.75, 99.85]  


d = {
    "college": str1,
    "branch": str2,
    "category": str3,
    "year": str4,
    "cutoff": str5
}

df = pd.DataFrame(d)
csv_file = 'cutoff.csv'
df.to_csv(csv_file, index=False)
print("Saved DataFrame:")
print(df)


df = pd.read_csv("cutoff.csv")
print("Loaded DataFrame:")
print(df)


df['college'] = df['college'].map({'COEP': 0})
df['branch'] = df['branch'].map({'Computer': 0})
df['category'] = df['category'].map({'OBC': 0})


reg = linear_model.LinearRegression()
reg.fit(df.drop('cutoff', axis='columns'), df.cutoff)


college = 0  
branch = 0   
category = 0 
year = int(input("Enter year (e.g. 2024): "))


prediction = reg.predict([[college, branch, category, year]])
print(f"Predicted cutoff is: {prediction[0]}")


new_data = {
    "college": ["COEP"],
    "branch": ["Computer"],
    "category": ["OBC"],
    "year": [year],
    "Predicted_Cutoff": [prediction[0]]
}

new_df = pd.DataFrame(new_data)
new_df.to_csv("prediction_result.csv", index=False)
print("Prediction saved to 'prediction_result.csv'")
