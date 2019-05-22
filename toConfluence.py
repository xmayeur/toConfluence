#!/usr/bin/env python
# coding: utf-8

import requests
import json
import sys
from getpass import getpass, getuser
import certifi
from os import listdir, getcwd, remove
from os.path import isfile, join, split
import argparse

try:
    from RSAcipher import RSAcipher
except:
    RSAcipher = None

SSLVerif = False
token_file = 'h:/.ssh/.token'

if SSLVerif:
    cacerts = certifi.where()
else:
    cacerts = False
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

title = "Service Model-Conceptual Service Model Overview"

target = 'Confluence'
user = None
pwd = None

if target == 'OrangeSharing':
    pageId = "93530158"
    pageID = None
    parentPageID = "89229458"
    url = "https://orangesharing.com/confluence/rest/api/content/"
    spaceKey = "CEA"
else:
    url = 'https://confluence.europe.intranet/rest/api/content/'
    pageID = None  # '725022273'
    parentPageID = "725984102"
    spaceKey = 'EAO'


def printResponse(r):
    print('{} {}\n'.format(json.dumps(r.json(), sort_keys=True, indent=4, separators=(',', ': ')), r))


def setConfluencePage(docPath=None, title='', pageId=None, spaceKey=None, parentPageId=None):
    # dummy get to log into
    r = requests.get(url, auth=(user, pwd), verify=cacerts)
    if r.status_code != 200:
        return r.status_code

    utitle = title.replace(" ", "%20")
    docName = title + ".wi"
    imgName = title + ".png"

    if pageID is None:
        # Search for a confluence page by title

        pageId = None

        # http://localhost:8080/confluence/rest/api/content?title=myPage%20Title&spaceKey=TST&expand=history"
        reqUrl = url + "?title=" + utitle + "&spaceKey=" + spaceKey + "&expand=history"
        r = requests.get(reqUrl, auth=(user, pwd), verify=cacerts)

        if r.status_code == 200:
            print(r)
            pageData = (r.json())
            results = pageData['results']
            if len(results) == 0:
                print('page not found')
            else:
                pageId = results[0]['id']
                print('Page ID: ' + pageId)
        else:
            printResponse(r)

    # open the existing Confluence page
    if pageId is not None:
        reqUrl = url + pageId  # +"?expand=body.storage"
        r = requests.get(reqUrl, auth=(user, pwd), verify=cacerts)

        # print(r.text)
        if r.status_code == 200:
            pageData = (r.json())
            # myBody = pageData['body']['storage']['value']
            key = pageData["space"]["key"]
            title = pageData["title"]
            print("Page title: " + title)
            parentPage = r.json()
        else:
            printResponse(r)

    # or create o new page  under the parent page
    else:
        newPageData = {
            'type': 'page',
            'title': title,
            "ancestors": [{"id": parentPageId}],
            'space': {'key': spaceKey},
            'body': {'storage': {'value': "_Empty_", 'representation': 'wiki'}}
        }
        r = requests.post(url,
                          data=json.dumps(newPageData),
                          auth=(user, pwd),
                          headers=({'Content-Type': 'application/json'}),
                          verify=cacerts)

        if r.status_code == 200:
            # Retrieve the new Page ID
            reqUrl = url + "?title=" + utitle + "&spaceKey=" + spaceKey + "&expand=history"
            r = requests.get(reqUrl, auth=(user, pwd), verify=cacerts)

            if r.status_code == 200:
                pageData = (r.json())
                results = pageData['results']
                if len(results) == 0:
                    print('page not found')
                else:
                    pageId = results[0]['id']
                    print('New Page ID: ' + pageId)
            else:
                printResponse(r)

                # upload or update the image associated to the page

    # check list of existing attachments
    # get attachments from the target Confluence page

    attId = ''

    reqUrl = url + pageId + "/child/attachment"
    r = requests.get(reqUrl, auth=(user, pwd), verify=cacerts)

    for a in r.json()['results']:
        print(a['title'] + ": " + a['id'])
        if imgName == a['title']:
            attId = a['id']
            break

    # upload attachment
    if attId != '':
        print('File ' + imgName + ' already exist... updating...')

        files = {'file': open(docPath + "/" + imgName, 'rb'), 'minorEdit': 'false', 'comment': 'Updated image '}
        r = requests.post(url + pageId + "/child/attachment/" + attId + '/data',
                          auth=(user, pwd),
                          headers=({'X-Atlassian-Token': 'no-check'}),
                          verify=cacerts,
                          files=files)

    else:
        print('Uploading a new attachment...')
        files = {'file': open(docPath + "/" + imgName, 'rb')}
        r = requests.post(url + pageId + "/child/attachment",
                          auth=(user, pwd),
                          headers=({'X-Atlassian-Token': 'no-check'}),
                          verify=cacerts,
                          files=files)

    if r.status_code != 200:
        printResponse(r)

    # Upload now the page body
    # Open the Confluence wiki formatted document and load its content

    with open(docPath + '\\' + docName, 'r') as f:
        docContent = f.read()

    # get the version number of the page to update
    if pageId is not None:
        r = requests.get(url + pageId + "?expand=version", auth=(user, pwd), verify=cacerts)

        if r.status_code == 200:
            pageData1 = (r.json())
            version = int(pageData1['version']['number']) + 1
            print("Document next version is: " + str(version))
        else:
            printResponse(r)
            version = 1

        # Replace and update the content of an existing page using XHTML storage format
        # Example 
        # curl -u admin:admin -X PUT -H 'Content-Type: application/json' -d '{"id":"3604482","type":"page",
        # "title":"new page","space":{"key":"TST"},"body":{"storage":{"value":
        # "<p>This is the updated text for the new page</p>","representation":"storage"}},
        # "version":{"number":2}}' http://localhost:8080/confluence/rest/api/content/3604482 | python -mjson.tool

        newPageData = {
            'type': 'page',
            'id': pageId,
            'title': title,
            'space': {'key': spaceKey},
            'version': {'number': version},
            'body': {'storage': {'value': docContent, 'representation': 'wiki'}}
        }

        r = requests.put(url + pageId,
                         data=json.dumps(newPageData),
                         auth=(user, pwd),
                         headers=({'Content-Type': 'application/json'}),
                         verify=cacerts)

        if r.status_code == 200:
            print("Page updated!")
        else:
            printResponse(r)

    return r.status_code


def main():
    global pageID, parentPageID, target,url, spaceKey, user, pwd

    parser = argparse.ArgumentParser("create or update Confluence page using wiki mardown files")

    parser.add_argument("-d", "--directory",
                        help="handle all .wi files in the specified directory")
    parser.add_argument("-id", "--pageid", required=False,
                        help="update using page ID instead of file name")
    parser.add_argument("-pid", "--parentid", required=False,
                        help="specify the parent page ID")
    parser.add_argument("-o", "--OrangeSharing", required=False, action='store_true',
                        help="specify the OrangeSharing as Confluence site")
    parser.add_argument('-k', '--spacekey', default='EAO',
                        help="specify the Confluence Space key - default is 'EAO'")
    parser.add_argument('file', nargs='?',
                        help="handle the specified file")
    args = parser.parse_args()

    if args.OrangeSharing:
        url = "https://orangesharing.com/confluence/rest/api/content/"
        if args.spacekey == 'EAO':
            spaceKey = "CEA"
        else:
            spaceKey = args.spacekey

        print('Publishing on orangeSharing')
    else:
        url = 'https://confluence.europe.intranet/rest/api/content/'
        spaceKey = args.spacekey

    # get user's credentials
    user = getuser()
    if RSAcipher is not None:
        try:
            with open(token_file, 'r') as f:
                token = f.read()
                rsa = RSAcipher('h:/.ssh/XY56RE.key')
                pwd = rsa.decrypt(token)
        except:
            pwd = None
            if isfile(token_file):
                remove(token_file)

    if pwd is None:
        pwd = getpass('Enter password for user ' + user + ": ")
        if RSAcipher is not None:
            with open(token_file, 'w') as f:
                rsa = RSAcipher('h:/.ssh/XY56RE.pub')
                token = rsa.encrypt(pwd)
                f.write(token)

    if args.pageid:
        pageID = args.pageid

    if args.parentid:
        parentPageID = args.parentid

    if args.directory:
        docPath = args.directory
        files = [f for f in listdir(docPath) if isfile(join(docPath, f))]
        for f in files:
            if ".wi" in f:
                print('file: ' + f)
                title = f.replace('.wi', '')
                code = setConfluencePage(docPath, title, pageID, spaceKey, parentPageID)
                if code == 401:
                    print("Authorization failure!")
                    if isfile(token_file):
                        remove(token_file)
                    sys.exit(1)
        sys.exit(0)

    if args.file:
        filePath = args.file
        fileRelative = filePath.split("\\")

        if len(fileRelative) == 1:
            docPath = getcwd()+ '\\'
        else:
            docPath = filePath[0:len(filePath) - len(fileRelative[len(fileRelative) - 1])]
        title = fileRelative[len(fileRelative) - 1].replace('.wi', '')
        print('docPath: ' + docPath + '\ntitle: ' + title)
        code = setConfluencePage(docPath, title, pageID, spaceKey, parentPageID)
        if code == 401:
            print("Authorization failure!")
            if isfile(token_file):
                remove(token_file)
            sys.exit(1)
        sys.exit(0)


if __name__ == "__main__":
    main()
