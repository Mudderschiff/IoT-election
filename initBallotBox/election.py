import tally_pb2
import json
import electionguard
import binascii
import paho.mqtt.client as mqtt
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from random import randint
import logging
import threading
import paho.mqtt.subscribe as subscribe
import pdb
import sys
from electionguard.hash import hash_elems
from electionguard.nonces import Nonces

from electionguard import SpecVersion, ElectionType, GeopoliticalUnit, ReportingUnitType, Party, Candidate, BallotStyle, \
    SelectionDescription, VoteVariationType, \
    ContestDescription

from electionguard.type import BallotId
from electionguard.utils import get_optional

# Step 0 - Configure Election
from electionguard.constants import ElectionConstants, create_constants, get_small_prime

from electionguard.election import CiphertextElectionContext
from electionguard.manifest import Manifest, InternalManifest

# Step 1 - Key Ceremony
from electionguard.group import hex_to_p, hex_to_q, int_to_q

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
from electionguard.chaum_pedersen import ChaumPedersenProof
from electionguard.decryption_share import (
    CiphertextDecryptionSelection,
    CiphertextDecryptionContest,
    DecryptionShare,
)
from electionguard.decrypt_with_shares import decrypt_tally

from electionguard.decryption_mediator import DecryptionMediator
from electionguard.election_polynomial import LagrangeCoefficientsRecord
from electionguard.key_ceremony import ElectionPublicKey

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
mutex = threading.Lock()


NUMBER_OF_GUARDIANS = 2
QUORUM = 2

manifest: Manifest
ciphertext_tally: CiphertextTally
decryption_mediator: DecryptionMediator

class SingleExecutionHandler:
    def __init__(self):
        self._executed = False
        self._lock = threading.Lock()

    def execute_once(self, func, *args, **kwargs):
        with self._lock:
            if not self._executed:
                self._executed = True
                func(*args, **kwargs)
                
                
build_election_handler = SingleExecutionHandler()

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

def parse_ciphertext_decryption_contest(data):
	return CiphertextDecryptionContest(
	object_id=data.object_id,
	guardian_id=data.guardian_id.hex(),
	description_hash=hex_to_q(data.description_hash.hex()),
	selections={int(selection_id): parse_ciphertext_decryption_selection(selection) for selection_id, selection in enumerate(data.selections)}
	)

def parse_decryption_share(data):
	return DecryptionShare(
	object_id=data.object_id,
	guardian_id=data.guardian_id.hex(),
    public_key=hex_to_p(data.public_key.hex()),
    contests={int(contest_id): parse_ciphertext_decryption_contest(contest) for contest_id, contest in enumerate(data.contests)}
    )

def parse_ciphertext_tally_selections(data):
	selection = tally_pb2.CiphertextTallySelectionProto()
	selection.object_id = data.object_id
	selection.ciphertext_pad = data.ciphertext.pad.value.to_bytes(384, byteorder='big')
	selection.ciphertext_data = data.ciphertext.data.value.to_bytes(384, byteorder='big')
	return selection
	

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
	

def parse_ciphertext_tally(tally, base_hash):
	ciphertext = tally_pb2.CiphertextTallyProto()
	ciphertext.object_id = tally.object_id
	ciphertext.base_hash = base_hash.value.to_bytes(32, byteorder='big')
	ciphertext.num_contest = len(tally.contests)
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
	

def _buildElection(message):
	global ciphertext_tally, decryption_mediator, manifest
	#print(f"Received message '{message.payload.decode()}' on topic '{message.topic}' with QoS {message.qos}")
	mqttc.unsubscribe("joint_key")
	election_builder: ElectionBuilder
	device: EncryptionDevice
	encrypter: EncryptionMediator
	ballot_box: BallotBox
	plaintext_ballots: List[PlaintextBallot]
	ciphertext_ballots: List[CiphertextBallot] = []
	submitted_ballots: Dict[BallotId, SubmittedBallot]
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
	 	
	plaintext_ballots = BallotFactory().generate_fake_plaintext_ballots_for_election(internal_manifest, 5, None, False, False)
	for plain in plaintext_ballots:
		for contest in plain.contests:
			for selection in contest.ballot_selections:
				if selection.vote == 1:
					print(f"Ballot ID: {plain.object_id}, Selected: {selection.object_id}")
		
	for plain in plaintext_ballots:
		encrypted_ballot = encrypter.encrypt(plain)
		ciphertext_ballots.append(get_optional(encrypted_ballot))
	
	ballot_store = DataStore()
	ballot_box = BallotBox(internal_manifest, context, ballot_store)
	
	for ballot in ciphertext_ballots:
		submitted_ballot = ballot_box.cast(ballot)

	ciphertext_tally = get_optional(tally_ballots(ballot_store, internal_manifest, context))
	submitted_ballots = get_ballots(ballot_store, BallotBoxState.SPOILED)
	#print(f"cast: {ciphertext_tally.cast()}")
	#print(f"spoiled: {ciphertext_tally.spoiled()}")
	submitted_ballots_list = list(submitted_ballots.values())
	
	decryption_mediator = DecryptionMediator("decryption-mediator", context)
	
	parsed_data = parse_ciphertext_tally(ciphertext_tally, context.crypto_extended_base_hash)
	serialized_message = parsed_data.SerializeToString()
	mqttc.publish("ciphertally", serialized_message, 2, False)
	mqttc.subscribe("decryption_share", 2)
	
	
	
def decrypt_tally()	-> None:
	global decryption_mediator, ciphertext_tally, manifest
	print("decrypt tally")
	plaintext_tally: PlaintextTally
	plaintext_tally = decryption_mediator.get_plaintext_tally(ciphertext_tally, manifest)
	print(plaintext_tally)
		
def process_share(client, userdata, message):
	
	deserialized = tally_pb2.DecryptionShareProto()
	deserialized.ParseFromString(message.payload)
	share = parse_decryption_share(deserialized)
	#print(share)
	print(f"Guardian Present: {deserialized.guardian_id.hex()}")
	with mutex:
		decryption_mediator.announce(ElectionPublicKey(owner_id=int(deserialized.guardian_id.hex(),16),sequence_order=int(deserialized.guardian_id.hex(),16),key=hex_to_p(deserialized.public_key.hex()),coefficient_commitments=[],coefficient_proofs=[]), share)
	if len(decryption_mediator._available_guardians) == QUORUM:
		with mutex:
			decrypt_tally()
		
		

def on_build_election(client, userdata, message):
    build_election_handler.execute_once(_buildElection, message)

	
manifest = createManifest()

electionguard.constants.STANDARD_CONSTANTS = create_constants(
	5809605995369958062859502533304574370686975176362895236661486152287203730997089013490246327149176617979883979879665474146725235639037470348294494756855649315623483381532284382829985865022634153578375633183351018921091870438603777296285300005007798125066694887162528853877672530170996389357750706590940588953424536914526358486709688983421547257618538163834967140534985203755017132605692672822700384056871677888971931895590561928921294273236194685526463354686525653654114179791182933523021406079633254465546599561197242920973013822820114343447081949390370753277569017722080197289385153614111846483012304466313627319490653728075778475634253896521588120585027626201092035118691290007496293626942041424997480127725248684036863793198217924529520768114832049450715656899658126803689999781406220992057283178444017598705139849562007174360175183917956509707878788742084753622778956841724673565867858641107428015367836415614107464499199,
	115792089237316195423570985008687907853269984665640564039457584007913129639747,  # pow(2, 256) - 189
	50172736614702193476010968685027850385725009984025754056752351897843540836809501857582622501011043805624882442705121527957457314216703019848506491542416048680150015176751863502045767527184617294497075084910496276997695216972542566310098645323089311784649009927959528878514066350803601544489238112989830818502071033067514117524130744776601302690867843065480705069205775202884218033343131500721992545187412682323348381061850505196518376963582336101914422155939209672462687958072229481112658285666828397567126306616634605158427548433669022805035656789286025402739180974848575290263903285848610951762542336807674715790221593229762571552817379724296274946311992728575342565996306922533232201850750304201504286745236639979257233112859066599580409049888412420870663129590514968528298497578450985177891114800807166167122028381365269811600460476934437467434,
	3983976838916583196990814207322510921320016467946417533216999154309346787158720745756708248623554944941202173601872329574166373683909547590349567059887290235949592851779429018520595520234297752071717586124672451539896760499203413787244838790030191769295209586115971156675352412376249718705430315603172039092707904550561519064313499331843446952946564189902025255748380139209555571060994585339534962548340004251462419027674037527180756962099450195292537848904334229156066064209226803823602255101468813019466466208165853013917347257777537304347349735373163087810141891329611178020461116524438016075431298306107501342366508266827438534566861633359768082249446920430439681449905774361889853764938857878702552850700522179471524761958893751061483523094674764719754250107548869925353603911589083937977401963462791699327224813999144150047728455687970145475131554558843766807046314831942872482690705753882915485571147817424402984387346,
	)

#h1 = hex_to_q("905B5E07803593CC53EFFE0513AEBD3552B2A4DA5C120B1B23BAB5B899C5D00D")
#h2 = hex_to_p("FF34566BDF05514EAF6E77425F31C38587E6B2B37F1A7F9BCFD816384BF5847EBEE97322A94824F64A593AE01EFE8C844AEDF69AF583E944B71E5620B36FA7A73E80FD33D879E44704D0349704F4AEE56B4B33E5DC8F02063BFD961D90E7DF51A61F202EB8E6999F3879B75BA6B6B45E3775467C501CA0765901B2B403E8E5C19F25C4C6CC655D30A5BDC2F817C92FD0A9807D514031B6841FB491DBF05ED8E2CEF056E97911D856D263C8C65E464F7CC1C5038E7166E5E438835F305260CB6BC090004E4036661B4316B7EE9D289424424E11E6510EB1DEDD88DC5D61FC2DBB823623A863855142CF63554F3E5D38DA07EE1469DF8DB4782AEB66BBEE5912CC882D70E9CB9DB3F63F90663E8D51AE8CAA46EB3E6D979EF7EA1F7FF6BE586C0D11D6B463053A791E1E34C0875EE2E75FA966BAE4A2DD0FA1213D941EA74A367B7B8289F6A22032B2C4220036033FFEE254882D73A85BD8FDABD76199715D7F370FF846EC2BA32A3AD01386942BB016DEF79A0E1093A02E81B73F3F372C748A50")
#h3 = hex_to_p("DED342D2901B76E3AC57BA39B9704085D171D6A4AE728881F5433DB9C8C3D2207D286EC76FF0F4E8D0045614CFB58983396B2B1D09D46ECAEDF7815CF7D286CF01707FBF34DBC2668B082A152571F9BF5B67737F6EBA8C66F31E9CA2F8641714226F32392A58CC09F83798A4BE9A4CBC46A6A39DD7E17904138B271021A6494456266D9CE977E49869703C8CE8C671324282C0C2C69E6E1AC7310A41721EAB03D6BD75EF66264706FE456EC5DE9C4212954AF26E660055DCF642FDF7E86854C086FF36C7E2D42F80011CE963C649B26FB37EF528ED4E4895A00B6D5CC8177B67615B19C1061A0AC8A35F7F9CA4FC9E1E8DD79B346F6351A2DBA4B4CEDD26C848EDAE0C0C077F2281EA453AE05555AFB7D70AF36D611896CBD109B0D733F7AB446A656C76BF2CD7F324079F45AA9FDC5EEAC0851F1028F8956B2C9255594219092CDEB032CA63521A12F62711FD8C1DE583DD602AFC2831C39DF8B49B35058E558D33A23349BE536507709DF69B78362ECEDBA0E11B77B667814DE374ED61EC45")
#h4 = hex_to_p("F2B15DB15EEB95C1FD7204DCE7C35F713A2494658277E79039D946D647B917D6EF42B3DAD0D824DCCD743729AA8E3212070A65BA8D0791E8C49578AE14C7672980B21D713050B4C0ABE008482BC31573129B2BE7D21FA373830EA297223E487F044071973392650E8D643E7A702634D1F0497B1BD63274DF5BC3E0179DDD683EFFE0450D1AEE9C1324BC5157C4A6140C905F3F85F2BD3E1DAFC63C337585F9DB955AA30D98C71B84A843567EAE9601B908A40034F5EC0FB4FBD7DE679BBCA5983C863D7BBD29EBB6FC87D847B6B84A584F4FBCB3A523F3970F79E03A89373778A9DA170B12BD7BF0027DD752C66167AA763CD2E961ADC3354DF09CE531FFC0F97491C4392C68D647E77FE91C0CEF7B141DBD600AB54B056705905D13D723E68440EF21CD9A0BBA4FDA9C51C071266E79537AD3DEBAFC2C725254251F7D2176825C4447E6CD61D4619077DC0460F10E7B8AB66CC9ADE1BAD2238EA50F01E085EFE407B0EBB360A50807963C98392EA6BDC2A1E37BD656A0936543357CB299A6D0")
#h5 = hex_to_p("414655783B7B3A92430056878FB55E46243BC159B492CC583EFB791F2342B7B1CC2BB852CE8DCB4D9FFE9F6568C70D3D8CC4D689280B21CD0590A279EC92E325602EA27E2F82248172EB17764217F6CBC7D4FF2D9B84F1D5C10CED87F9464BADCC5BD43E5EA65D066971FC8B4A5ECE857E9452137E2695FF6DA0EE8786EFA2EDA25FBE8900FDEAD68FA0E25176E2B91A5BB8E6FFA1C41FBF6C8256A346F6652777E0F1C4321A629F23380F5DBEFD9AA7D0457BF4B2599A5839C14B0B9ACA0FA7DCD83704F7D0F2034CADC1C1838DF21390AD4BA15181D863E5D07C75E7BF829DEC15620AD377A28AB064A148D8C84F945A54834ABE4296A1AC1FCC6DC43E3B20DD0B9503E07BBBC7837ED6725A8385A89911B5765FB37C0879D23A69BAFDCC3DBD7159B107558FC91B2C1C7FF479AB9679364F2C180C25D25BC73EEFC66F11053809B7CAE35F634F2014F8145A0BE5BA5B3853549CB0116EBC37D6395494CC047EFB4AD4C53B349E5BE61A2950F81495282B6DFB826F307BD30528DAE4079618")
#h6 = hex_to_p("9EB312E096134106A92D22F2A6BF7C72DB518FDFA62C3BE62923665DA6310E96652629F4353AEBFE7482BB819EC956FD3C83DEE5E251A412EDE69DCCB53E70C48DF9772549C876363ED11067A39DD731F98C21D783F1E961C76108E1BAE34FC2BDE7ACFCE8ED8203ADD9022B87B739C75117CC489E9AE4EEBEF687683A06BE6180B1C29A360460EDB82529ADF85F4763B4093EADFDE896BB5358B83948270AB27DF72B83143D65381EB0F6614B9EC772748D98E8E7C4297E1E57D28CB7277A3F0D9606760384267601518D7CB6D4D61A08F5130A3E18596B8446E4274157D07C6A0E83C5AD1BDFD8D7543032D21ECE13E51F8FB248E507F45C97DA76EB816DCF50F7EABEE2A26CDFC24D6D3EF131F22B1A77893C80F015461AC2B08B59BA348B56103C09D11B31249FC697AF9FBF13EF8EAB6B3222E5CAB18031D81B150809FE9EEEA752AC63E769D73BF1C86C7FD5656315CA0A80775BC970D77B94D45D874D54B0095A2428EC54E49266EF4B024265325F64862B5BDD4C78A81B95D1E4C0A2")
#0A670782598AEA11D34BD0EC413054033C33A731D8421743195172A4118E7ADC
#b = str(0)
#print(b.encode("utf-8"))
#seed = hex_to_q("5FCFB59F318CA12CA29ACE93818567CC069737980F68481715ADBD9244499EE4")
#u = Nonces(seed, "constant-chaum-pedersen-proof")[0]
#print(u)

mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)    
#mqttc.on_message = on_message
mqttc.connect("192.168.12.1", 1883, 60)
mqttc.message_callback_add("joint_key", on_build_election)
mqttc.message_callback_add("decryption_share", process_share)

# Send election information. Set retain flag in order for newly subscribed clients to receive the election information.
message = f"{QUORUM},{NUMBER_OF_GUARDIANS}"
mqttc.publish("ceremony_details", message, 2, False)
mqttc.subscribe("joint_key", 2)

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


