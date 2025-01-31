import tally_pb2
import json
import electionguard
import binascii
import paho.mqtt.client as mqtt
from datetime import datetime, timedelta
from typing import List, Dict
from random import randint
import logging


from electionguard import SpecVersion, ElectionType, GeopoliticalUnit, ReportingUnitType, Party, Candidate, BallotStyle, \
    SelectionDescription, VoteVariationType, \
    ContestDescription

from electionguard.type import BallotId
from electionguard.utils import get_optional

# Step 0 - Configure Election
from electionguard.constants import ElectionConstants, create_constants

from electionguard.election import CiphertextElectionContext
from electionguard.manifest import Manifest, InternalManifest

# Step 1 - Key Ceremony
from electionguard.group import hex_to_p, hex_to_q
#from electionguard.guardian import Guardian, GuardianRecord, PrivateGuardianRecord
#from electionguard.key_ceremony_mediator import KeyCeremonyMediator

# Step 2 - Encrypt Votes
from electionguard.ballot import (
    BallotBoxState,
    CiphertextBallot,
    PlaintextBallot,
    SubmittedBallot,
)
from electionguard.encrypt import EncryptionDevice
from electionguard.encrypt import EncryptionMediator

# Step 3 - Cast and Spoil
from electionguard.data_store import DataStore
from electionguard.ballot_box import BallotBox, get_ballots, submit_ballot

# Step 4 - Decrypt Tally
from electionguard.tally import (
    PublishedCiphertextTally,
    tally_ballots,
    CiphertextTally,
    PlaintextTally,
)
from electionguard.decryption_mediator import DecryptionMediator
from electionguard.election_polynomial import LagrangeCoefficientsRecord

# Step 5 - Publish and Verify
from electionguard.serialize import from_file, construct_path
from electionguard_tools.helpers.export import (
    COEFFICIENTS_FILE_NAME,
    DEVICES_DIR,
    GUARDIANS_DIR,
    PRIVATE_DATA_DIR,
    SPOILED_BALLOTS_DIR,
    SUBMITTED_BALLOTS_DIR,
    ELECTION_RECORD_DIR,
    SUBMITTED_BALLOT_PREFIX,
    SPOILED_BALLOT_PREFIX,
    CONSTANTS_FILE_NAME,
    CONTEXT_FILE_NAME,
    DEVICE_PREFIX,
    ENCRYPTED_TALLY_FILE_NAME,
    GUARDIAN_PREFIX,
    MANIFEST_FILE_NAME,
    TALLY_FILE_NAME,
    export_private_data,
    export_record,
)

from electionguard_tools.helpers.election_builder import ElectionBuilder
from electionguard_tools.factories.election_factory import ElectionFactory
from electionguard_tools.factories.ballot_factory import BallotFactory


logger = logging.getLogger("electionguard")
logger.setLevel(logging.WARNING)

# Step 0 - Configure Election
manifest: Manifest
election_builder: ElectionBuilder
internal_manifest: InternalManifest
context: CiphertextElectionContext
constants: ElectionConstants
NUMBER_OF_GUARDIANS = 2
QUORUM = 2

# Step 1
JOINT_KEY_SIZE = 384
COMMITMENT_SIZE = 32
joint_key = None
commitment = None

# Step 2 - Encrypt Votes
device: EncryptionDevice
encrypter: EncryptionMediator
plaintext_ballots: List[PlaintextBallot]
ciphertext_ballots: List[CiphertextBallot] = []

# Step 3 - Cast and Spoil
ballot_store: DataStore[BallotId, SubmittedBallot]
ballot_box: BallotBox
ballot_box_ballot: SubmittedBallot
submitted_ballots: Dict[BallotId, SubmittedBallot]

# Step 4 - Decrypt Tally
ciphertext_tally: CiphertextTally
plaintext_tally: PlaintextTally
plaintext_spoiled_ballots: Dict[str, PlaintextTally]
decryption_mediator: DecryptionMediator
lagrange_coefficients: LagrangeCoefficientsRecord


#def parse_ciphertext_tally_selection(data):
#    selection = tally_pb2.CiphertextTallySelectionProto()
#    print("Object id")
#    print("description hash")
#    description_hash = data.description_hash
#    print(description_hash)
#    print("Ciphertext pad")
#    ciphertext_pad = data.ciphertext.pad
#    print(ciphertext_pad)
#    print("ciphertext data")
#    ciphertext_data = data.ciphertext.data
#    print(ciphertext_data)
#    selection.object_id = data.object_id
#    selection.description_hash = description_hash.value.to_bytes((description_hash.value.bit_length() + 7) // 8, byteorder='big')
#    selection.ciphertext_pad = ciphertext_pad.value.to_bytes((ciphertext_pad.value.bit_length() + 7) // 8, byteorder='big')
#    selection.ciphertext_data = ciphertext_data.value.to_bytes((ciphertext_data.value.bit_length() + 7) // 8, byteorder='big')
#    return selection

#def parse_ciphertext_tally_selections(data, base_hash):
#    selections = tally_pb2.CiphertextTallySelectionsProto()
#    print(base_hash)
#    selections.base_hash = base_hash.value.to_bytes((base_hash.value.bit_length() + 7) // 8, byteorder='big')
#    selections.num_selections = len(data.selections)
#    print("Num selections")
#    print(selections.num_selections)
#    for value in data.selections.values():
#        selection = parse_ciphertext_tally_selection(value)
#        selections.selections.append(selection)
#    return selections

#message CiphertextTallySelectionProto {
#	required string object_id = 1;
#	required bytes ciphertext_pad = 2;
#	required bytes ciphertext_data = 3;
#}

def parse_ciphertext_tally_selections(data):
	selection = tally_pb2.CiphertextTallySelectionProto()
	print("Object Id, Ciphertext Pad, Ciphertext Data")
	print(data.object_id)
	print(data.ciphertext.pad)
	print(data.ciphertext.data)
	selection.object_id = data.object_id
	selection.ciphertext_pad = data.ciphertext.pad.value.to_bytes((data.ciphertext.pad.value.bit_length() + 7) // 8, byteorder='big')
	selection.ciphertext_data = data.ciphertext.data.value.to_bytes((data.ciphertext.data.value.bit_length() + 7) // 8, byteorder='big')
	return selection
	

def parse_ciphertext_tally_contests(data):
	contests = tally_pb2.CiphertextTallyContestProto()
	contests.object_id = data.object_id
	contests.sequence_order = data.sequence_order
	contests.description_hash = data.description_hash.value.to_bytes((data.description_hash.value.bit_length() + 7) // 8, byteorder='big')
	contests.num_selections = len(data.selections)
	print("Object ID, Dequence Order, Description Hash, Num Selections")
	print(data.object_id)
	print(data.sequence_order)
	print(data.description_hash)
	print(contests.num_selections)
	for value in data.selections.values():
		selection = parse_ciphertext_tally_selections(value)
		contests.selections.append(selection)
	return contests
	

def parse_ciphertext_tally(tally, base_hash):
	ciphertext = tally_pb2.CiphertextTallyProto()
	ciphertext.object_id = tally.object_id
	ciphertext.base_hash = base_hash.value.to_bytes((base_hash.value.bit_length() + 7) // 8, byteorder='big')
	ciphertext.num_contest = len(tally.contests)
	print("Object ID, Base Hash, Num COntests")
	print(tally.object_id)
	print(base_hash)
	print(ciphertext.num_contest)
	for value in tally.contests.values():
		contest = parse_ciphertext_tally_contests(value)
		ciphertext.contests.append(contest)
	return ciphertext


def createManifest() -> Manifest:
	print("Created with number_of_guardians:", NUMBER_OF_GUARDIANS)
	print("Created with quorum:", QUORUM)
	
	ballot_style_single_vote = BallotStyle("ballot-style-single-vote")
	ballot_style_single_vote.geopolitical_unit_ids = ["single-vote"]
	# A contest is a collection of candidates and/or referendum options where the voter may make a selection
	referendum_ballot_selections = [
    # Referendum selections are simply a special case of `candidate` in the object model
		SelectionDescription("yes-selection", 0, "YES"),
		SelectionDescription("no-selection", 1, "NO"),
		SelectionDescription("abstain-selection", 2, "ABSTAIN"),
	]
	referendum_single_vote_contest = ContestDescription("referendum-single-vote",0,"single-vote",VoteVariationType.one_of_m,1,1,"Referendum Single Vote Contest",referendum_ballot_selections,)
	manifest = Manifest(
    spec_version=SpecVersion.EG1_0,
    election_scope_id="esn-manifest",
    type=ElectionType.general,
    start_date=datetime.now(),
    end_date=datetime.now() + timedelta(hours=1),
    geopolitical_units=[
        GeopoliticalUnit(
            "single-vote",
            "Single Vote",
            ReportingUnitType.ballot_batch,
        )
    ],
    parties=[Party("N/A")],
    candidates=[
        Candidate("YES"),
        Candidate("NO"),
        Candidate("ABSTAIN"),
    ],
    contests=[referendum_single_vote_contest],
    ballot_styles=[ballot_style_single_vote],
	)
	
	print(
    f"""
            {'-'*40}\n
            # Election Summary:
            # Scope: {manifest.election_scope_id}
            # Geopolitical Units: {len(manifest.geopolitical_units)}
            # Parties: {len(manifest.parties)}
            # Candidates: {len(manifest.candidates)}
            # Contests: {len(manifest.contests)}
            # Ballot Styles: {len(manifest.ballot_styles)}\n
            {'-'*40}\n
            """
	)
	if(manifest.is_valid()):
		return manifest
	
def buildElection() -> None:
	global election_builder, joint_key, commitment, internal, constants, device, encrypter, plaintext_ballots, ciphertext_ballots, ballot_box, submitted_ballots, ballot_store, ciphertext_tally, plaintext_tally, plaintext_spoiled_ballots,decryption_mediator,lagrange_coefficients,ballot_box_ballot
	
	election_builder = ElectionBuilder(NUMBER_OF_GUARDIANS, QUORUM, manifest)
	election_builder.set_public_key(hex_to_p(joint_key))
	election_builder.set_commitment_hash(hex_to_q(commitment))

	
	internal_manifest, context = get_optional(election_builder.build())
	
	device = ElectionFactory.get_encryption_device()
	encrypter = EncryptionMediator(internal_manifest, context, device)
	 
	#print(internal_manifest.get_ballot_style(ballot-style-single-vote)) 
	
	plaintext_ballots = BallotFactory().generate_fake_plaintext_ballots_for_election(internal_manifest, 5, None, False, False)
	for plain in plaintext_ballots:
		print("PLaintextballot")
		print(plain)
		for contest in plain.contests:
			for selection in contest.ballot_selections:
				if selection.vote == 1:
					print(f"Ballot ID: {plain.object_id}, Selected: {selection.object_id}")
		
	for plain in plaintext_ballots:
		print("CiphertextBallot")
		encrypted_ballot = encrypter.encrypt(plain)
		print(encrypted_ballot)
		ciphertext_ballots.append(get_optional(encrypted_ballot))
	
	ballot_store = DataStore()
	ballot_box = BallotBox(internal_manifest, context, ballot_store)
	
	for ballot in ciphertext_ballots:
		submitted_ballot = ballot_box.cast(ballot)

	ciphertext_tally = get_optional(tally_ballots(ballot_store, internal_manifest, context))
	submitted_ballots = get_ballots(ballot_store, BallotBoxState.SPOILED)
	print(f"cast: {ciphertext_tally.cast()}")
	print(f"spoiled: {ciphertext_tally.spoiled()}")
	#print(f"Total: {ciphertext_tally}")
	submitted_ballots_list = list(submitted_ballots.values())
	decryption_mediator = DecryptionMediator("decryption-mediator",context,)
	
	parsed_data = parse_ciphertext_tally(ciphertext_tally, context.crypto_extended_base_hash)
	serialized_message = parsed_data.SerializeToString()
	mqttc.publish("ciphertally", serialized_message, 0, False)
	mqttc.subscribe("decryption_share")

	
	
def on_message(mosq, obj, msg):
	global commitment, joint_key
	#print(msg.topic + " " + str(msg.qos) + " " + str(msg.payload))
	if msg.topic == "joint_key":
		mosq.unsubscribe("joint_key")
		buffer = msg.payload
		joint_key = binascii.hexlify(buffer[:JOINT_KEY_SIZE]).decode('utf-8')
		commitment = binascii.hexlify(buffer[JOINT_KEY_SIZE:JOINT_KEY_SIZE + COMMITMENT_SIZE]).decode('utf-8')
		buildElection()
	if msg.topic == "decryption_share":
		buffer = msg.payload
		deserialized = tally_pb2.DecryptionShareProto()
		deserialized.ParseFromString(buffer)
		print(deserialized)
		
		
		

	
manifest = createManifest()

electionguard.constants.STANDARD_CONSTANTS = create_constants(
	5809605995369958062859502533304574370686975176362895236661486152287203730997089013490246327149176617979883979879665474146725235639037470348294494756855649315623483381532284382829985865022634153578375633183351018921091870438603777296285300005007798125066694887162528853877672530170996389357750706590940588953424536914526358486709688983421547257618538163834967140534985203755017132605692672822700384056871677888971931895590561928921294273236194685526463354686525653654114179791182933523021406079633254465546599561197242920973013822820114343447081949390370753277569017722080197289385153614111846483012304466313627319490653728075778475634253896521588120585027626201092035118691290007496293626942041424997480127725248684036863793198217924529520768114832049450715656899658126803689999781406220992057283178444017598705139849562007174360175183917956509707878788742084753622778956841724673565867858641107428015367836415614107464499199,
	115792089237316195423570985008687907853269984665640564039457584007913129639747,  # pow(2, 256) - 189
	50172736614702193476010968685027850385725009984025754056752351897843540836809501857582622501011043805624882442705121527957457314216703019848506491542416048680150015176751863502045767527184617294497075084910496276997695216972542566310098645323089311784649009927959528878514066350803601544489238112989830818502071033067514117524130744776601302690867843065480705069205775202884218033343131500721992545187412682323348381061850505196518376963582336101914422155939209672462687958072229481112658285666828397567126306616634605158427548433669022805035656789286025402739180974848575290263903285848610951762542336807674715790221593229762571552817379724296274946311992728575342565996306922533232201850750304201504286745236639979257233112859066599580409049888412420870663129590514968528298497578450985177891114800807166167122028381365269811600460476934437467434,
	3983976838916583196990814207322510921320016467946417533216999154309346787158720745756708248623554944941202173601872329574166373683909547590349567059887290235949592851779429018520595520234297752071717586124672451539896760499203413787244838790030191769295209586115971156675352412376249718705430315603172039092707904550561519064313499331843446952946564189902025255748380139209555571060994585339534962548340004251462419027674037527180756962099450195292537848904334229156066064209226803823602255101468813019466466208165853013917347257777537304347349735373163087810141891329611178020461116524438016075431298306107501342366508266827438534566861633359768082249446920430439681449905774361889853764938857878702552850700522179471524761958893751061483523094674764719754250107548869925353603911589083937977401963462791699327224813999144150047728455687970145475131554558843766807046314831942872482690705753882915485571147817424402984387346,
	)

mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)    
mqttc.on_message = on_message
mqttc.connect("192.168.12.1", 1883, 60)
# Send election information. Set retain flag in order for newly subscribed clients to receive the election information.
message = f"{QUORUM},{NUMBER_OF_GUARDIANS}"
mqttc.publish("ceremony_details", message, 2, False)
mqttc.subscribe("joint_key")

mqttc.loop_forever()


