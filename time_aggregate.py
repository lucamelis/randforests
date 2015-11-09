import pandas as pd

def hour_groupper(df_logs, n_hours):
	"""
	logs dataframe and #hours as input
	create new attribute timestamp
	return new dataframe and groupby (8)per timestamp
	"""
	import datetime as dt
	
	def f(x):
		s = [int(i) for i in x.time.split(":")]
		return dt.datetime.combine(x.D,dt.time(*s))
	

	df_logs["t"] = df_logs.apply(f,axis=1)
	df_gr = df.groupby(pd.Grouper(key="t",freq=str(n_hours)+'H'))
	
	return df_logs, df_gr

# n_hours = 8
# df = pd.read_pickle("data/df_sample_2015-02-13.pkl")

# df, gr = hour_groupper(df,8)
