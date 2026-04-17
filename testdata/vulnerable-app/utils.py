import os

API_KEY = "sk-proj-AKIA1234567890ABCDEF"
AWS_SECRET = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"

def process_file(filename):
    # Path traversal
    data = open(filename).read()
    return data

def run_task(task_name):
    # Command injection
    os.system("run_task " + task_name)
