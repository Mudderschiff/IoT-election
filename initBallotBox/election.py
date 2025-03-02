import tally_pb2
import electionguard
import binascii
import paho.mqtt.client as mqtt
from datetime import datetime, timedelta
from typing import List, Dict
from random import randint
import logging
import threading
import sys

from electionguard import SpecVersion, ElectionType, GeopoliticalUnit, ReportingUnitType, Party, Candidate, BallotStyle, \
    SelectionDescription, VoteVariationType, \
    ContestDescription

from electionguard.type import BallotId
from electionguard.utils import get_optional
from electionguard.constants import create_constants
from electionguard.election import CiphertextElectionContext
from electionguard.manifest import Manifest, InternalManifest
from electionguard.group import hex_to_p, hex_to_q
from electionguard.encrypt import EncryptionDevice, EncryptionMediator
from electionguard.decrypt_with_shares import decrypt_tally
from electionguard.decryption_mediator import DecryptionMediator
from electionguard.key_ceremony import ElectionPublicKey
from electionguard_tools.helpers.election_builder import ElectionBuilder
from electionguard_tools.factories.election_factory import ElectionFactory
from electionguard_tools.factories.ballot_factory import BallotFactory
from electionguard_tools.helpers.tally_accumulate import accumulate_plaintext_ballots
from electionguard.data_store import DataStore
from electionguard.ballot_box import BallotBox
from electionguard.chaum_pedersen import ChaumPedersenProof

from electionguard.ballot import (
    CiphertextBallot,
    PlaintextBallot,
    SubmittedBallot,
)
from electionguard.tally import (
    tally_ballots,
    CiphertextTally,
    PlaintextTally,
)
from electionguard.decryption_share import (
    CiphertextDecryptionSelection,
    CiphertextDecryptionContest,
    DecryptionShare,
)

logger = logging.getLogger("electionguard")
logger.setLevel(logging.WARNING)
mutex = threading.Lock()


NUMBER_OF_GUARDIANS = 2
QUORUM = 2

manifest: Manifest
ciphertext_tally: CiphertextTally
decryption_mediator: DecryptionMediator

## @brief Ensures a function is only executed once, even if called multiple times from different threads.
class SingleExecutionHandler:
	    ## @brief Initializes a new instance of the SingleExecutionHandler.
    def __init__(self):
		## @var _executed
        #  A boolean flag indicating whether the function has been executed.
        self._executed = False
        self._lock = threading.Lock()

    ## @brief Executes the given function only once.
    #  @param func The function to execute.
    #  @param *args Arguments to pass to the function.
    #  @param **kwargs Keyword arguments to pass to the function
    def execute_once(self, func, *args, **kwargs):
        with self._lock:
            if not self._executed:
                self._executed = True
                func(*args, **kwargs)
                
                
build_election_handler = SingleExecutionHandler()

## @brief Parses a CiphertextDecryptionSelectionProto object from protobuf data.
#
#  This function converts the protobuf representation of a ciphertext decryption selection
#  into an `electionguard.decryption_share.CiphertextDecryptionSelection` object.
#
#  @param data The protobuf data representing the ciphertext decryption selection.
#  @return A `CiphertextDecryptionSelection` object
def parse_ciphertext_decryption_selection(data):
	return CiphertextDecryptionSelection(
	object_id=data.object_id,
	guardian_id=data.guardian_id.hex(),
	share=hex_to_p(data.decryption.hex()),
	proof=ChaumPedersenProof(
		pad=hex_to_p(data.proof_pad.hex()),
		data=hex_to_p(data.proof_data.hex()),
		challenge=hex_to_q(data.proof_challenge.hex()),
		response=hex_to_q(data.proof_response.hex())
	)
	)

## @brief Parses a CiphertextDecryptionContestProto object from protobuf data.
#
#  This function converts the protobuf representation of a ciphertext decryption contest
#  into an `electionguard.decryption_share.CiphertextDecryptionContest` object.
#
#  @param data The protobuf data representing the ciphertext decryption contest.
#  @return A `CiphertextDecryptionContest` object.
def parse_ciphertext_decryption_contest(data):
	return CiphertextDecryptionContest(
	object_id=data.object_id,
	guardian_id=data.guardian_id.hex(),
	description_hash=hex_to_q(data.description_hash.hex()),
	selections={int(selection_id): parse_ciphertext_decryption_selection(selection) for selection_id, selection in enumerate(data.selections)}
	)

## @brief Parses a DecryptionShareProto object from protobuf data.
#
#  This function converts the protobuf representation of a decryption share
#  into an `electionguard.decryption_share.DecryptionShare` object.
#
#  @param data The protobuf data representing the decryption share.
#  @return A `DecryptionShare` object.
def parse_decryption_share(data):
	return DecryptionShare(
	object_id=data.object_id,
	guardian_id=data.guardian_id.hex(),
    public_key=hex_to_p(data.public_key.hex()),
    contests={int(contest_id): parse_ciphertext_decryption_contest(contest) for contest_id, contest in enumerate(data.contests)}
    )

## @brief Parses a CiphertextTallySelection from protobuf data.
#
#  This function converts the protobuf representation of a ciphertext tally selection
#  into a `tally_pb2.CiphertextTallySelectionProto` object.
#
#  @param data The protobuf data representing the ciphertext tally selection.
#  @return A `tally_pb2.CiphertextTallySelectionProto` object.
def parse_ciphertext_tally_selections(data):
	selection = tally_pb2.CiphertextTallySelectionProto()
	selection.object_id = data.object_id
	selection.ciphertext_pad = data.ciphertext.pad.value.to_bytes(384, byteorder='big')
	selection.ciphertext_data = data.ciphertext.data.value.to_bytes(384, byteorder='big')
	return selection
	
## @brief Parses a CiphertextTallyContest from protobuf data.
#
#  This function converts the protobuf representation of a ciphertext tally contest
#  into a `tally_pb2.CiphertextTallyContestProto` object.
#
#  @param data The protobuf data representing the ciphertext tally contest.
#  @return A `tally_pb2.CiphertextTallyContestProto` object.
def parse_ciphertext_tally_contests(data):
	contests = tally_pb2.CiphertextTallyContestProto()
	contests.object_id = data.object_id
	contests.sequence_order = data.sequence_order
	contests.description_hash = data.description_hash.value.to_bytes(32, byteorder='big')
	contests.num_selections = len(data.selections)
	for value in data.selections.values():
		selection = parse_ciphertext_tally_selections(value)
		contests.selections.append(selection)
	return contests
	
## @brief Parses a CiphertextTally from a tally object and base hash.
#
#  This function converts an `electionguard.tally.CiphertextTally` object into its protobuf
#  representation as a `tally_pb2.CiphertextTallyProto` object.
#
#  @param tally The `CiphertextTally` object to parse.
#  @param base_hash The base hash to include in the protobuf representation.
#  @return A `tally_pb2.CiphertextTallyProto` object.
def parse_ciphertext_tally(tally, base_hash):
	ciphertext = tally_pb2.CiphertextTallyProto()
	ciphertext.object_id = tally.object_id
	ciphertext.base_hash = base_hash.value.to_bytes(32, byteorder='big')
	ciphertext.num_contest = len(tally.contests)
	for value in tally.contests.values():
		contest = parse_ciphertext_tally_contests(value)
		ciphertext.contests.append(contest)
	return ciphertext

## @brief Creates a Manifest object defining the election.
#
#  This function constructs an `electionguard.manifest.Manifest` object with predefined
#  election parameters, including geopolitical units, parties, candidates, contests, and ballot styles.
#
#  @return A `Manifest` object representing the election definition.
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
	
## @brief Builds the election context and generates an encrypted tally.
#
#  This function performs the core election setup. It also generates
#  random ballots and cast them. All cast ballots are tallied and the resulting
#  encrypted tally is published to the MQTT broker.
#
#  @param message The MQTT message containing the joint key and commitment.
def _buildElection(message):
	global ciphertext_tally, decryption_mediator, manifest
	mqttc.unsubscribe("joint_key")
	election_builder: ElectionBuilder
	device: EncryptionDevice
	encrypter: EncryptionMediator
	ballot_box: BallotBox
	plaintext_ballots: List[PlaintextBallot]
	ciphertext_ballots: List[CiphertextBallot] = []
	ballot_store: DataStore[BallotId, SubmittedBallot]
	context: CiphertextElectionContext
	internal_manifest: InternalManifest
	
	JOINT_KEY_SIZE = 384
	COMMITMENT_SIZE = 32
	
	buffer = message.payload
	joint_key = binascii.hexlify(buffer[:JOINT_KEY_SIZE]).decode('utf-8')
	commitment = binascii.hexlify(buffer[JOINT_KEY_SIZE:JOINT_KEY_SIZE + COMMITMENT_SIZE]).decode('utf-8')
	
	election_builder = ElectionBuilder(NUMBER_OF_GUARDIANS, QUORUM, manifest)
	election_builder.set_public_key(hex_to_p(joint_key))
	election_builder.set_commitment_hash(hex_to_q(commitment))

	internal_manifest, context = get_optional(election_builder.build())

	device = ElectionFactory.get_encryption_device()
	encrypter = EncryptionMediator(internal_manifest, context, device)
	 	
	print("Generating Random Ballots")	
	plaintext_ballots = BallotFactory().generate_fake_plaintext_ballots_for_election(internal_manifest, 1000, None, False, False)
	for plain in plaintext_ballots:
		for contest in plain.contests:
			for selection in contest.ballot_selections:
				if selection.vote == 1:
					print(f"Ballot ID: {plain.object_id}, Selected: {selection.object_id}")

	expected_result = accumulate_plaintext_ballots(plaintext_ballots)
	print("Expected Result: ", expected_result)

	for plain in plaintext_ballots:
		encrypted_ballot = encrypter.encrypt(plain)
		ciphertext_ballots.append(get_optional(encrypted_ballot))
	
	ballot_store = DataStore()
	ballot_box = BallotBox(internal_manifest, context, ballot_store)
	
	for ballot in ciphertext_ballots:
		ballot_box.cast(ballot)

	ciphertext_tally = get_optional(tally_ballots(ballot_store, internal_manifest, context))
	
	decryption_mediator = DecryptionMediator("decryption-mediator", context)
	
	parsed_data = parse_ciphertext_tally(ciphertext_tally, context.crypto_extended_base_hash)
	serialized_message = parsed_data.SerializeToString()
	mqttc.publish("ciphertally", serialized_message, 2, False)
	
	
	
## @brief Decrypts the tally using the decryption mediator and prints the results.
#
#  This function retrieves the plaintext tally from the decryption mediator,
#  then extracts and prints the tally for each selection in the contest.
def decrypt_tally()	-> None:
	global decryption_mediator, ciphertext_tally, manifest
	print("decrypt tally")
	plaintext_tally: PlaintextTally
	plaintext_tally = decryption_mediator.get_plaintext_tally(ciphertext_tally, manifest)
	result = plaintext_tally.contests['referendum-single-vote']
	tally: Dict[str, int] = {}
	for selection in result.selections.values():
		tally[selection.object_id] = selection.tally
	print("Tally Result: ", tally)
	mqttc.publish("finished", "", 0, False)



## @brief Processes a decryption share received via MQTT.
#
#  This function deserializes the decryption share from the MQTT message, announces
#  the share to the decryption mediator, and triggers the tally decryption if enough
#  shares have been received.
#
#  @param client The MQTT client instance.
#  @param userdata User-defined data passed to the callback.
#  @param message The MQTT message containing the decryption share.	
def process_share(client, userdata, message):
	
	deserialized = tally_pb2.DecryptionShareProto()
	deserialized.ParseFromString(message.payload)
	share = parse_decryption_share(deserialized)
	print(f"Guardian Present: {deserialized.guardian_id.hex()}")
	with mutex:
		decryption_mediator.announce(ElectionPublicKey(owner_id=int(deserialized.guardian_id.hex(),16),sequence_order=int(deserialized.guardian_id.hex(),16),key=hex_to_p(deserialized.public_key.hex()),coefficient_commitments=[],coefficient_proofs=[]), share)
	if len(decryption_mediator._available_guardians) == QUORUM:
		with mutex:
			decrypt_tally()
		
		
## @brief Handles the "joint_key" MQTT message to build the election.
#
#  This function is a callback that is executed when a message is received on the "joint_key" MQTT topic.
#  It calls the `_buildElection` function to build the election context and process ballots.
#  It uses a `SingleExecutionHandler` to ensure that the `_buildElection` function is only executed once.
#
#  @param client The MQTT client instance.
#  @param userdata User-defined data passed to the callback.
#  @param message The MQTT message containing the joint key
def on_build_election(client, userdata, message):
	election_thread = threading.Thread(target=_buildElection, args=(message,))
	election_thread.start()
    #build_election_handler.execute_once(_buildElection, message)

	
manifest = createManifest()

# Set the reduced baseline parameters for the election
electionguard.constants.STANDARD_CONSTANTS = create_constants(
	5809605995369958062859502533304574370686975176362895236661486152287203730997089013490246327149176617979883979879665474146725235639037470348294494756855649315623483381532284382829985865022634153578375633183351018921091870438603777296285300005007798125066694887162528853877672530170996389357750706590940588953424536914526358486709688983421547257618538163834967140534985203755017132605692672822700384056871677888971931895590561928921294273236194685526463354686525653654114179791182933523021406079633254465546599561197242920973013822820114343447081949390370753277569017722080197289385153614111846483012304466313627319490653728075778475634253896521588120585027626201092035118691290007496293626942041424997480127725248684036863793198217924529520768114832049450715656899658126803689999781406220992057283178444017598705139849562007174360175183917956509707878788742084753622778956841724673565867858641107428015367836415614107464499199,
	115792089237316195423570985008687907853269984665640564039457584007913129639747,  # pow(2, 256) - 189
	50172736614702193476010968685027850385725009984025754056752351897843540836809501857582622501011043805624882442705121527957457314216703019848506491542416048680150015176751863502045767527184617294497075084910496276997695216972542566310098645323089311784649009927959528878514066350803601544489238112989830818502071033067514117524130744776601302690867843065480705069205775202884218033343131500721992545187412682323348381061850505196518376963582336101914422155939209672462687958072229481112658285666828397567126306616634605158427548433669022805035656789286025402739180974848575290263903285848610951762542336807674715790221593229762571552817379724296274946311992728575342565996306922533232201850750304201504286745236639979257233112859066599580409049888412420870663129590514968528298497578450985177891114800807166167122028381365269811600460476934437467434,
	3983976838916583196990814207322510921320016467946417533216999154309346787158720745756708248623554944941202173601872329574166373683909547590349567059887290235949592851779429018520595520234297752071717586124672451539896760499203413787244838790030191769295209586115971156675352412376249718705430315603172039092707904550561519064313499331843446952946564189902025255748380139209555571060994585339534962548340004251462419027674037527180756962099450195292537848904334229156066064209226803823602255101468813019466466208165853013917347257777537304347349735373163087810141891329611178020461116524438016075431298306107501342366508266827438534566861633359768082249446920430439681449905774361889853764938857878702552850700522179471524761958893751061483523094674764719754250107548869925353603911589083937977401963462791699327224813999144150047728455687970145475131554558843766807046314831942872482690705753882915485571147817424402984387346,
	)

mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)    
mqttc.connect("192.168.12.1", 1883, 60)
mqttc.message_callback_add("joint_key", on_build_election)
mqttc.message_callback_add("decryption_share", process_share)

# Send election information. Set retain flag in order for newly subscribed clients to receive the election information.
message = f"{QUORUM},{NUMBER_OF_GUARDIANS}"
mqttc.publish("ceremony_details", message, 2, False)
mqttc.subscribe("joint_key", 2)
mqttc.subscribe("decryption_share", 1)

try:
    mqttc.loop_forever()
except KeyboardInterrupt:
    print("Interrupted by user (Ctrl+C)")
    mqttc.disconnect()
    sys.exit(0)
except Exception as e:
    print(f"An error occurred: {e}")
    mqttc.disconnect()
    sys.exit(1)


