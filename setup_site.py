import subprocess
import os

def run():
    with open('install_full.log', 'w') as f:
        subprocess.run(['pip', 'install', '-r', 'requirements.txt'], stdout=f, stderr=f, shell=True)
    
    # We won't block here for the server, but we can try to start it
    # subprocess.Popen(['python', 'dil_main.py'], stdout=open('server_full.log', 'w'), stderr=subprocess.STDOUT)
    # Actually, let's just do the install first to see if it works.

if __name__ == "__main__":
    run()
