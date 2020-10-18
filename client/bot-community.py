#!/usr/bin/python3
import argparse
import subprocess
import geojson

from math import sqrt, ceil
from random_word import RandomWords
from pyproj import Geod
geoid = Geod(ellps='WGS84')

cli = ["../target/release/encointer-client-notee"]

NUMBER_OF_LOCATIONS = 10
MAX_POPULATION = 12 * NUMBER_OF_LOCATIONS

def move_point(point, az, dist):
    """ move a point a certain distance [meters] into a direction (azimuth) in [degrees] """

    lng_new, lat_new, return_az = geoid.fwd(point['coordinates'][0], point['coordinates'][1], az, dist)
    return geojson.Point([lng_new, lat_new])

def populate_locations(northwest, n, dist=1000):
    """ populate approximately n locations on a square grid of a specified distance in meters """
    row = [ northwest ]
    for li in range(1, round(sqrt(n))):
        row.append(move_point(row[-1], 90, dist))
    locations = []
    for pnt in row:
        col = [ pnt ]
        for li in range(1, round(sqrt(n))):
            col.append(move_point(col[-1], 180, dist))
        locations += col
    return locations

def next_phase():
    subprocess.run(cli + ["next-phase"])
    
def get_phase():    
    ret = subprocess.run(cli + ["get-phase"], stdout=subprocess.PIPE)
    return ret.stdout.strip().decode("utf-8")

def list_accounts():
    ret = subprocess.run(cli + ["list-accounts"], stdout=subprocess.PIPE)
    return ret.stdout.decode("utf-8").splitlines()

def new_account():
    ret = subprocess.run(cli + ["new-account"], stdout=subprocess.PIPE)
    return ret.stdout.decode("utf-8").strip()

def faucet(accounts):
    subprocess.run(cli + ["faucet"] + accounts, stdout=subprocess.PIPE)

def balance(accounts, **kwargs):
    bal = []
    cid_arg = []
    if 'cid' in kwargs:
        cid_arg = ["--cid", kwargs.get('cid')]
    for account in accounts:
        ret = subprocess.run(cli + cid_arg + ["balance", account], stdout=subprocess.PIPE)
        bal.append(float(ret.stdout.strip().decode("utf-8").split(' ')[-1]))
    return bal

def new_currency(specfile):
    ret = subprocess.run(cli + ["new-currency", specfile, '//Alice'], stdout=subprocess.PIPE)
    return ret.stdout.decode("utf-8").strip()

def await_block():
    subprocess.run(cli + ["listen", "-b", "1"], stdout=subprocess.PIPE)

def register_participant(account, cid):
    ret = subprocess.run(cli + ["--cid", cid, "register-participant", account], stdout=subprocess.PIPE)
    #print(ret.stdout.decode("utf-8"))

def new_claim(account, vote, cid):
    ret = subprocess.run(cli + ["--cid", cid, "new-claim", account, str(vote)], stdout=subprocess.PIPE)
    return ret.stdout.decode("utf-8").strip()

def sign_claim(account, claim):
    ret = subprocess.run(cli + ["sign-claim", account, claim], stdout=subprocess.PIPE)
    return ret.stdout.decode("utf-8").strip()

def list_meetups(cid):
    ret = subprocess.run(cli + ["--cid", cid, "list-meetups"], stdout=subprocess.PIPE)
    #print(ret.stdout.decode("utf-8"))
    meetups = []
    lines = ret.stdout.decode("utf-8").splitlines()
    while len(lines) > 0:
        if 'participants are:' in lines.pop(0):
            participants = []
            while len(lines) > 0:
                l = lines.pop(0)
                if 'MeetupRegistry' in l:
                    break
                participants.append(l.strip())
            meetups.append(participants)
    return meetups

def register_attestations(account, attestations):
    ret = subprocess.run(cli + ["register-attestations", account] + attestations, stdout=subprocess.PIPE)
    #print(ret.stdout.decode("utf-8"))


def generate_currency_spec(name, locations, bootstrappers):
    gj = geojson.FeatureCollection(list(map(lambda x : geojson.Feature(geometry=x), locations)))
    gj['currency_meta'] = { 'name': name, 'bootstrappers': bootstrappers }
    fname = name + '.json'
    with open(fname, 'w') as outfile:
        geojson.dump(gj, outfile)
    return fname
    
def random_currency_spec(nloc):
    point = geojson.utils.generate_random("Point", boundingBox=[-56, 41, -21, 13])
    locations = populate_locations(point, NUMBER_OF_LOCATIONS)
    print("created " + str(len(locations)) + " random locations around " + str(point))
    bootstrappers = []
    for bi in range(0,10):
        bootstrappers.append(new_account())
    print('new bootstrappers:' + ' '.join(bootstrappers))
    faucet(bootstrappers)
    await_block()
    name = 'currencyspec-' + '-'.join(RandomWords().get_random_words(limit=3))
    return generate_currency_spec(name, locations, bootstrappers)

def init():
    print("initializing community")
    specfile = random_currency_spec(16)
    print("generated currency spec: ", specfile)
    cid = new_currency(specfile)
    print("created community with cid: ", cid)
    f = open("cid.txt", "w")
    f.write(cid)
    f.close()

def run():
    f = open("cid.txt", "r")
    cid = f.read()
    print("cid is " + cid)
    phase = get_phase()
    print("phase is " + phase)
    accounts = list_accounts()
    print("number of known accounts: " + str(len(accounts)))
    if phase == 'REGISTERING':
        bal = balance(accounts, cid=cid)
        total = sum(bal)
        print("****** money supply is " + str(total))
        f = open("bot-stats.csv", "a")
        f.write(str(len(accounts)) + ", " + str(total) + "\n")
        f.close()
        if total > 0:
            n_newbies = min(ceil(len(accounts) / 4.0), MAX_POPULATION - len(accounts))
            print("*** adding " + str(n_newbies) + " newbies")
            if n_newbies > 0:
                newbies = []
                for n in range(0,n_newbies):
                    newbies.append(new_account())
                faucet(newbies)
                await_block()
                accounts = list_accounts()

        print("registering " + str(len(accounts)) + " participants")
        for p in accounts:
            #print("registering " + p)
            register_participant(p, cid)
        await_block()
    if phase == 'ATTESTING':
        meetups = list_meetups(cid)
        print("****** Performing " + str(len(meetups)) + " meetups")
        for meetup in meetups:
            n = len(meetup)
            print("Performing meetup with " + str(n) + " participants")
            claims = {}
            for p in meetup:
                claims[p] = new_claim(p, n, cid)
            for claimant in meetup:
                attestations = []
                for attester in meetup:
                    if claimant == attester:
                        continue
                    #print(claimant + " is attested by " + attester)
                    attestations.append(sign_claim(attester, claims[claimant]))
                #print("registering attestations for " + claimant)
                register_attestations(claimant, attestations)
        await_block()

def benchmark():            
    print("will grow population forever")
    while True:
        run()
        await_block
        next_phase()
        await_block

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='bot-community')
    subparsers = parser.add_subparsers(dest='subparser', help='sub-command help')
    parser_a = subparsers.add_parser('init', help='a help')
    parser_b = subparsers.add_parser('run', help='b help')
    parser_c = subparsers.add_parser('benchmark', help='b help')

    kwargs = vars(parser.parse_args())
    try:
        globals()[kwargs.pop('subparser')](**kwargs)
    except KeyError:
        parser.print_help()
