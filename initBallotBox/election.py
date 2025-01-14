import json
import binascii
import paho.mqtt.client as mqtt
from datetime import datetime, timedelta
from typing import List, Dict

from electionguard import SpecVersion, ElectionType, GeopoliticalUnit, ReportingUnitType, Party, Candidate, BallotStyle, \
    SelectionDescription, VoteVariationType, \
    ContestDescription

from electionguard.type import BallotId

# Step 0 - Configure Election
from electionguard.constants import ElectionConstants
from electionguard.election import CiphertextElectionContext
from electionguard.manifest import Manifest, InternalManifest
import electionguard.group

# Step 1 - Key Ceremony
from electionguard.guardian import Guardian, GuardianRecord, PrivateGuardianRecord
from electionguard.key_ceremony_mediator import KeyCeremonyMediator

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
from electionguard.ballot_box import BallotBox, get_ballots

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
submitted_ballots: Dict[BallotId, SubmittedBallot]



def createManifest() -> Manifest:
	print("Created with number_of_guardians:", NUMBER_OF_GUARDIANS)
	print("Created with quorum:", QUORUM)
	
	ballot_style_single_vote = BallotStyle("ballot-style-single-vote")
	ballot_style_single_vote.geopolitical_unit_ids = ["single-vote"]
	# A contest is a collection of candidates and/or referendum options where the voter may make a selection
	candidate_ballot_selections = [
		# "object_id", "sequence_order", "candidate_id"
		SelectionDescription("candidate-1-selection", 0, "CANDIDATE-1"),
		SelectionDescription("candidate-2-selection", 1, "CANDIDATE-2"),
		SelectionDescription("candidate-3-selection", 2, "CANDIDATE-3"),
	]
	referendum_ballot_selections = [
    # Referendum selections are simply a special case of `candidate` in the object model
		SelectionDescription("yes-selection", 0, "YES"),
		SelectionDescription("no-selection", 1, "NO"),
		SelectionDescription("abstain-selection", 2, "ABSTAIN"),
	]
	referendum_single_vote_contest = ContestDescription("referendum-single-vote",0,"single-vote",VoteVariationType.one_of_m,1,1,"Referendum Single Vote Contest",referendum_ballot_selections,)
	election_single_vote_contest = ContestDescription("election-single-vote",1,"single-vote",VoteVariationType.one_of_m,1,1,"Election Single Vote Contest",candidate_ballot_selections,)
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
        Candidate("CANDIDATE-1"),
        Candidate("CANDIDATE-2"),
        Candidate("CANDIDATE-3"),
        Candidate("YES"),
        Candidate("NO"),
        Candidate("ABSTAIN"),
    ],
    contests=[referendum_single_vote_contest, election_single_vote_contest],
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
	global election_builder, joint_key, commitment, internal, constants
	election_builder.set_public_key(hex_to_p(joint_key))
	election_builder.set_commitment_hash(hex_to_q(commitment))
	internal_manifest, context = get_optional(election_builder.build())
	constants = create_constants(
    5809605995369958062859502533304574370686975176362895236661486152287203730997089013490246327149176617979883979879665474146725235639037470348294494756855649315623483381532284382829985865022634153578375633183351018921091870438603777296285300005007798125066694887162528853877672530170996389357750706590940588953424536914526358486709688983421547257618538163834967140534985203755017132605692672822700384056871677888971931895590561928921294273236194685526463354686525653654114179791182933523021406079633254465546599561197242920973013822820114343447081949390370753277569017722080197289385153614111846483012304466313627319490653728075778475634253896521588120585027626201092035118691290007496293626942041424997480127725248684036863793198217924529520768114832049450715656899658126803689999781406220992057283178444017598705139849562007174360175183917956509707878788742084753622778956841724673565867858641107428015367836415614107464499199,
    115792089237316195423570985008687907853269984665640564039457584007913129639747,  # pow(2, 256) - 189
    50172736614702193476010968685027850385725009984025754056752351897843540836809501857582622501011043805624882442705121527957457314216703019848506491542416048680150015176751863502045767527184617294497075084910496276997695216972542566310098645323089311784649009927959528878514066350803601544489238112989830818502071033067514117524130744776601302690867843065480705069205775202884218033343131500721992545187412682323348381061850505196518376963582336101914422155939209672462687958072229481112658285666828397567126306616634605158427548433669022805035656789286025402739180974848575290263903285848610951762542336807674715790221593229762571552817379724296274946311992728575342565996306922533232201850750304201504286745236639979257233112859066599580409049888412420870663129590514968528298497578450985177891114800807166167122028381365269811600460476934437467434,
    3983976838916583196990814207322510921320016467946417533216999154309346787158720745756708248623554944941202173601872329574166373683909547590349567059887290235949592851779429018520595520234297752071717586124672451539896760499203413787244838790030191769295209586115971156675352412376249718705430315603172039092707904550561519064313499331843446952946564189902025255748380139209555571060994585339534962548340004251462419027674037527180756962099450195292537848904334229156066064209226803823602255101468813019466466208165853013917347257777537304347349735373163087810141891329611178020461116524438016075431298306107501342366508266827438534566861633359768082249446920430439681449905774361889853764938857878702552850700522179471524761958893751061483523094674764719754250107548869925353603911589083937977401963462791699327224813999144150047728455687970145475131554558843766807046314831942872482690705753882915485571147817424402984387346,
	)
	
	
def on_message(mosq, obj, msg):
	global commitment, joint_key
	#print(msg.topic + " " + str(msg.qos) + " " + str(msg.payload))
	if msg.topic == "joint_key":
		mosq.unsubscribe("joint_key")
		buffer = msg.payload
		joint_key = buffer[:JOINT_KEY_SIZE]
		commitment = buffer[JOINT_KEY_SIZE:JOINT_KEY_SIZE + COMMITMENT_SIZE]
		print("Joint Key:", binascii.hexlify(joint_key).decode('utf-8'))
		print("Commitment:", binascii.hexlify(commitment).decode('utf-8'))
		
    # This callback will be called for messages that we receive that do not
    # match any patterns defined in topic specific callbacks, i.e. in this case
    # those messages that do not have topics $SYS/broker/messages/# nor
    # $SYS/broker/bytes/#

	
manifest = createManifest()

mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)    
mqttc.on_message = on_message
mqttc.connect("192.168.12.1", 1883, 60)
# Send election information. Set retain flag in order for newly subscribed clients to receive the election information.
message = f"{QUORUM},{NUMBER_OF_GUARDIANS}"
mqttc.publish("ceremony_details", message, 2, True)
mqttc.subscribe("joint_key")

mqttc.loop_forever()


