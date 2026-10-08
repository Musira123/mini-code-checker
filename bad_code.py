import hashlib
import pickle
import subprocess

password = "admin1234"

user_input = input("Enter something: ")
result = eval(user_input)

hashed = hashlib.md5(b"hello").hexdigest()

data = pickle.loads(b"some bytes")

subprocess.run("ls " + user_input, shell=True)
