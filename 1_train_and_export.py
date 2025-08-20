# 1_train_and_export.py (with more rows)

import h2o
from h2o.automl import H2OAutoML
import pandas as pd
import os
import math
h2o.init()

# Create synthetic dataset with at least 10 rows
domains = [
    'google.com', 'ajskdflsd.biz', 'yahoo.com', 'x1y2z3abc.info', 'facebook.com',
    'zmxncbvqw.com', 'amazon.com', 'asdlkfjas.biz', 'github.com', 'lskdjfwer.net'
]

data = []
for d in domains:
    length = len(d)
    entropy = round(-sum((d.count(c) / length) * math.log2(d.count(c) / length) for c in set(d)), 2)
    label = 'legit' if 'com' in d and not any(c.isdigit() for c in d) else 'dga'
    data.append({'domain': d, 'length': length, 'entropy': entropy, 'label': label})

df = pd.DataFrame(data)

os.makedirs("data", exist_ok=True)
df.to_csv("data/dga_dataset_train.csv", index=False)

# Train model
h2o_df = h2o.import_file("data/dga_dataset_train.csv")
h2o_df['label'] = h2o_df['label'].asfactor()

# Drop domain column
h2o_df = h2o_df.drop('domain')

aml = H2OAutoML(max_models=5, seed=42)
aml.train(y='label', training_frame=h2o_df)

# Save MOJO
os.makedirs("model", exist_ok=True)
mojo_path = aml.leader.download_mojo(path="model", get_genmodel_jar=True)
print(f"Model saved to: {mojo_path}")
