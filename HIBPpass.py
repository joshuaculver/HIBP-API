"""
Filename: HIBPpass.py

Created by: Joshua Culver
Last edited by: Joshua Culver

Creation date: 12/6/2021
Last edit date: 12/8/2021

A program which uses the HIBP APIv3 to find the number of breaches if any for a password using it's SHA1 hash
"""
import requests
import csv
import sys

#CSV file to read passed as argument
#This can also be changed to a filename directly for input
csvread = sys.argv[1]
#CSV filename which will be written into
csvwrite = "hashOut"

fields = []
hashList = []
current = ['','']

#Opens csv file and retrieves value from each
with open(csvread, 'r') as csvread:
    reader = csv.reader(csvread)
    fields = next(reader)
    fields.append("breaches")
    
    #Makes a list of all rows in csv file
    for row in reader:
        hashList.append(row)

#Opens output file to write results into
with open(csvwrite, 'w') as csvwrite:
    writer = csv.writer(csvwrite)

    #Adds fields from input file 
    writer.writerow(fields)

    #Iterates through items in csv file 
    for i in hashList:
        hash = i[0]
        current[0] = i[0]
    
        #Seperates the first five characters and the rest of the hash
        check1 = hash[0:5]
        check2 = hash[5:].upper()

        #API returns the rest of SHA1 hashes which have the passed first five characters
        r = requests.get('https://api.pwnedpasswords.com/range/' + check1)

        #Looks for a matching hash using second part of given hash
        index = r.text.find(check2)

        #Check if a match was found or not
        if index != -1:
            #Get the index for where the number of breaches appears in the matches' row value
            start = r.text.find(':', index) + 1
            end = r.text.find('\n', index)

            current[1] = r.text[start:end]
            current[1] = int(current[1])

            #Writes hash and number of breaches to CSV file
            writer.writerow(current)
        else:
            #No matches so no breaches found
            current[1] = 0

            writer.writerow(current)

print("Finished check.")