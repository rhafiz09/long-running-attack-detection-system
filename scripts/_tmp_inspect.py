import pandas as pd, sys
sys.stdout.reconfigure(encoding='utf-8')

cols = ['Log Date','IP Address (Origin)','IP Address (Impacted)',
        'TCP/UDP Port (Impacted)','Zone (Origin)','Zone (Impacted)',
        'Log Source','Classification','Threat Name']

df = pd.read_csv(r'datasets/raw/firewall_log.csv', usecols=cols, nrows=300000)

print(f'Total rows: {len(df):,}')
print(f'Date range: {df["Log Date"].min()} --> {df["Log Date"].max()}')
print(f'Null Log Date: {df["Log Date"].isna().sum()}')
print(f'Null IP Origin: {df["IP Address (Origin)"].isna().sum()}')
print(f'Null Port: {df["TCP/UDP Port (Impacted)"].isna().sum()}')
print()
print('=== Classification distribution ===')
print(df['Classification'].value_counts())
print()
print('=== Top 10 IP Origin ===')
print(df['IP Address (Origin)'].value_counts().head(10))
print()
print('=== Log Source breakdown ===')
print(df['Log Source'].value_counts())
print()
print('=== Zone values ===')
print('Zone Origin:', df['Zone (Origin)'].dropna().unique()[:10])
print('Zone Impacted:', df['Zone (Impacted)'].dropna().unique()[:10])
