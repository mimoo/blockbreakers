# -*- coding: utf-8 -*-
# HTTP server
import threading
import SimpleHTTPServer
import SocketServer
# watcher
import sys
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
# template
from jinja2 import Template
import codecs # to read file in unicode

def generate():
    #
    # AES
    #

    AES_path = 'AES/'

    # Generation of AES sections
    ff = codecs.open("AES/template_section.html", "r", "utf-8")
    template = ff.read()
    ff.close()

    AES = [
        {
            'title':'The Key Expansion Part 1: RotWord',
            'path': '1_rotword.html',
            'image': 'aes_icons-02.jpg',
            'description': 'To transform a plaintext into a ciphertext, AES makes it undergo a number of transformations, one of them is to XOR it with keys. Since we only provide AES with <strong>a single key</strong>, AES will need to derive a number of keys from it.',
        },
         
        {
            'title': 'The Key Expansion Part 2: SubWord',
            'path': '2_subword.html',
            'image': 'aes_icons-03.jpg',
            'description':'The next helper function we\'ll need for our key Expansion is SubWord. SubWord takes an input of 4 bytes like the previous function, and returns an output of 4 bytes as well. SubWord is basically an <strong>Sbox</strong>.',
        },
        
        {
            'title': 'The Key Expansion Part 3: Rcon',
            'path': '3_rcon.html',
            'image': 'aes_icons-04.jpg',
            'description':'The last helper function <strong>Rcon</strong> takes an integer as input, and gives back an array of 4 bytes with the 3 least significant bytes set to 0.',
            },
        {
            'title': 'The Key Expansion',
            'path': '4_key_scheduler.html',
            'image': 'aes_icons-01.jpg',
            'description':"We've got all of the functions we need to implement the key scheduler! So let's finally get to it :)",
            },
        {
            'title': 'Understanding the State of AES',
            'path': '5_state.html',
            'image': 'aes_icons-05.jpg',
            'description':'The plaintext that AES manipulates is represented as a square of 4 rows and 4 columns.',
            },
        {
            'title': 'SubBytes',
            'path': '6_subbytes.html',
            'image': 'aes_icons-06.jpg',
            'description':"AES-128 has 10 rounds in total. Each round takes a different round key and the last round is a bit different from the other rounds. (The last round skips the MixColumns transformation.) With that in mind we will start by implementing SubBytes, the first transformation in an AES round.",
            },
        {
            'title': 'ShiftRows',
            'path': '7_shiftrows.html',
            'image': 'aes_icons-07.jpg',
            'description':"Our second transformation, ShiftRows, is a pretty simple one! It takes a state, look at its rows and rotate them. The first row doesn't get touched, the second one gets rotated by one position on the left, the second by two positions and the third by three positions.",
            },
        {
            'title': 'MixColumns',
            'path': '8_mixcolumns.html',
            'image': 'aes_icons-08.jpg',
            'description':"Now, on to our third round transformation. And surprise! It's another one of these AES operations that use the weird field we talked about in Rcon",
            },
        {
            'title': 'AddRoundKey',
            'path': '9_addroundkey.html',
            'image': 'aes_icons-09.jpg',
            'description':"The last transformation of a round is called AddRoundKey, and at this point you probably have an idea of what it is. And you're also probably right, it is just a XOR between the values in the state, and the values of your round key.",
            },
        {
            'title': 'Encryption',
            'path': '10_encryption.html',
            'image': 'aes_icons-10.jpg',
            'description':"Now is time to combine all of the functions we've been implementing into one big Encryption function.",
            },
        {
            'title': 'Decryption',
            'path': '11_decryption.html',
            'image': 'aes_icons-11.jpg',
            'description':"That's cool, you can encrypt and all. But what about decrypting :)",
        },
    ]

    for idx, section in enumerate(AES):
        # content
        ff = codecs.open(AES_path + section['path'], "r", "utf-8")
        content = ff.read()
        ff.close()
        html = Template(template)
        # percent
        percent = (idx+1) * 100.0 / len(AES)
        # next link
        nextlink = False
        if idx != len(AES) - 1:
            nextlink = AES[idx + 1]["path"]
        # title
        title = str(idx+1) + ". " + section['title']
        section['title'] = title
        # render
        ff = codecs.open("aes_" + section['path'], "w", "utf-8")

        ff.write(html.render(title=title, content=content, percent=percent, nextlink=nextlink))#, image=section['image']))
        ff.close()

    # Generation of AES homepage
    ff = codecs.open(AES_path + "template_index.html", "r", "utf-8")
    index_page = Template(ff.read())
    ff.close()

    ff = codecs.open("aes.html", "w", "utf-8")
    ff.write(index_page.render(sections=AES))
    ff.close()

    #
    # SQUARE
    #

    SQUARE_path = 'SQUARE/'

    # Generation of SQUARE sections
    ff = codecs.open("SQUARE/template_section.html", "r", "utf-8")
    template = ff.read()
    ff.close()

    SQUARE = [
        {
            'title':'A persistent structure over 3 rounds',
            'path': '1_3rounds.html',
            'image': 'square_icons-01.jpg',
            'description': 'Imagine <strong>a set of 256 plaintexts</strong>. All filled with 0s.',
        },
         
        {
            'title': 'Attacking 4 rounds with the Square attack',
            'path': '2_attack4rounds.html',
            'image': 'square_icons-02.jpg',
            'description':u"Remember what happened to our Λ-set after we've reached the end of 3 rounds",
        },
        
        
        {
            'title': 'Reversing AES\' Key Schedule',
            'path': '3_key_schedule.html',
            'image': 'square_icons-04.jpg',
            'description':"Now that we have obtained the last round key of our 3-round AES instance, we need to finish the job and reverse the key schedule to obtain the main key.",
            },
        
        {
            'title': 'Attacking 5 rounds with the Square attack',
            'path': '4_attack5rounds.html',
            'image': 'square_icons-05.jpg',
            'description':"Now that we've broken 4-round AES, let's try and see what we can do if we add an extra round at the end to make it a 5-round AES.",
            },
        {
            'title': 'Attacking 6 rounds with the Square attack',
            'path': '5_attack6rounds.html',
            'image': 'square_icons-06.jpg',
            'description':"We can also gain a round in the very beginning, we need to guess 4 key byte of the first subkey to create a delta set AFTER the first round.",
        },
    ]

    for idx, section in enumerate(SQUARE):
        # content
        ff = codecs.open(SQUARE_path + section['path'], "r", "utf-8")
        content = ff.read()
        ff.close()
        html = Template(template)
        # percent
        percent = (idx+1) * 100.0 / len(SQUARE)
        # next link
        nextlink = False
        if idx != len(SQUARE) - 1:
            nextlink = SQUARE[idx + 1]["path"]
        # render
        ff = codecs.open("square_" + section['path'], "w", "utf-8")
        ff.write(html.render(title=section['title'], content=content, percent=percent, nextlink=nextlink))#, image=section['image']))
        ff.close()

    # Generation of SQUARE homepage
    ff = codecs.open(SQUARE_path + "template_index.html", "r", "utf-8")
    index_page = Template(ff.read())
    ff.close()

    ff = codecs.open("square.html", "w", "utf-8")
    ff.write(index_page.render(sections=SQUARE))
    ff.close()



class MyHandler(FileSystemEventHandler):
    def on_modified(self, event):
        print "file modified"
        generate()

def watch():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    paths = ["AES", "SQUARE"]

    event_handler = MyHandler()
    observer = Observer()
    for path in paths:
        observer.schedule(event_handler, path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def serve():
    PORT = 8000
    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(("", PORT), Handler)
    print "serving at port", PORT
    httpd.serve_forever()

if __name__ == "__main__":
    # run server
    ff = threading.Thread(target=serve)
    ff.daemon = True
    ff.start()
    # run watcher
    watch()

