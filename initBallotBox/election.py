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

h1 = hex_to_q("89E73D120610EDBB0004135B2A30430D6C4CDA9B14B13540BEEC915754C5850E")
h2 = hex_to_p("8EE4384495F0F3822B87AA1CFA04065C5131DFAE8E24E64647478437521F2D2DFB3BF59269D7771CA19141D7BC4208B2C4D9036E4E23C340BB2F1974ED1D429B10B28BE3E520379AB1EBFCF49A7593CB7E54D16F6B84819395DD57B4DB1A30F243FB22BD8B6B7E206DFCED5D35C11626AF2FB42B1953461565A2B6E0D28B5040DCFB92A382C3B0B228919EEB75DDA182591DBD3A24AA5D2FDB9111C0B2C019F806973455D1E7F755391B520255EBF02AE664C0B61F9688FEDA638B34C163D6A4260FAE66042511F6722F589545EA0B82E4D649B49D2179EC537E901D9B7B2409519D1D5F5BE9C0D37B93242F613F113DE6740CBFA05ACDBAAC5596CBBD0BAB2191F3E5CE389F0E26A37956A00ABE5C643EAA6C2406BBEB8E7806EE89D704DC319A0340E1FB9FD6A8C176D314D8EFC6558E522E6B58C12B55169CA63C42BA9A98C4E830B61F8A1DF03B3EAC39BE5FBBDEC3C92F16C48369300FED6C18F16F283562982DA0FA7D28290A183DF5E80CAE8A4FE48561CD2262D95D6EEE65B8F50C2B")
h3 = hex_to_p("AD9F8B47390107FFFAA6E967224A11EEABE25FE6AEF2AB848B8A9E7474128F93EDDB16A62055BED03430DEBB5769ACAEFDFA3200112E9E83AC332F575B409254A41A4710627A5B74ADA11D9FCA0CB4A628F062010A116F5DE3CF07262D7D2CA625CB44EE195CC4EE9091FEFB827D1F9913141E1ECA08014C91D7AA87B9C79782C9826D2B7B1A79AC6ECE72249A3982ECC564841B9B46CE77E4BB19190E80150B32761576D37795EC46978AD470AA023F9F18EBA3A515E9E27404364EA5FCA722297F273CA92D035EC69157B372B3A5B7E8BAFF23DCAFB9416484418BA2EC54EC72331D5707CF0E219733EF82C142FEAF54774F1A3AE0601AACD2259BA6049504BF4887D2D922A64AB2EBF2D834F3EBB087406254B9ABB28731B81F33CD6BA3CB51332061F87723A49E2F181F570A20C0D6EF95C77A86DEFFBC86C2A5D867143BB6CE0F4547E8E96EEE47865AFF918ADD962BF93D0F3EB0DA6C4AACE1A45292B64CB196B64FF84A748580C67B4EC593AF902A79424F826BFF4F594DFA6776E191")
h4 = hex_to_p("F2B15DB15EEB95C1FD7204DCE7C35F713A2494658277E79039D946D647B917D6EF42B3DAD0D824DCCD743729AA8E3212070A65BA8D0791E8C49578AE14C7672980B21D713050B4C0ABE008482BC31573129B2BE7D21FA373830EA297223E487F044071973392650E8D643E7A702634D1F0497B1BD63274DF5BC3E0179DDD683EFFE0450D1AEE9C1324BC5157C4A6140C905F3F85F2BD3E1DAFC63C337585F9DB955AA30D98C71B84A843567EAE9601B908A40034F5EC0FB4FBD7DE679BBCA5983C863D7BBD29EBB6FC87D847B6B84A584F4FBCB3A523F3970F79E03A89373778A9DA170B12BD7BF0027DD752C66167AA763CD2E961ADC3354DF09CE531FFC0F97491C4392C68D647E77FE91C0CEF7B141DBD600AB54B056705905D13D723E68440EF21CD9A0BBA4FDA9C51C071266E79537AD3DEBAFC2C725254251F7D2176825C4447E6CD61D4619077DC0460F10E7B8AB66CC9ADE1BAD2238EA50F01E085EFE407B0EBB360A50807963C98392EA6BDC2A1E37BD656A0936543357CB299A6D0")
h5 = hex_to_p("54705874684D4286B2330509C91D1036EE92222FAB7E613554BB76ACF70B8B53F273FE2F8282BEA79E42D1212863EADB4236B98521C1A4657E07239541E6855785C7DA958AFD8B64E4ACC9E79803FAFC3115357593A37764B2B2D0B049454FF2ED0E33AB57F9A79DD9031110FA554B6827DC0F6FE0A99A85B3E690218B2B69128852EFECA7BF159AF58C863EA83E0574E9DF4957BBF6FFC83F2DD76F0168D56AA3E590091418D6D5FCAA611C1E9EB4BEBF41C983BDC379742E91CA07F74C5240E905BBAE11C50AAEF4B4028083A76C9B9F5509E55B8063528ED8BB7265F1071D4345B6AB5E5B5862E1270122E53F9BB7BD8B77902EABCB7659D53B604F82043694A5C0D146947A88CCA467AADB5709E3C6B84B655DC02BDE35DC83EF3138CBA034FD1911A26326489386CB65B66A53F7493FD1DB4786DAE2F1E3ED0F4A962B4E698A946F08553B1B67441F8AF6FAD1C03D0FAE56293E009594B6A231B895CFD5B5FB0C8153A264A2B4658D895D795B12ED4FFDE97CF02E4DB9C01171DA787281")
h6 = hex_to_p("EA08C4079374BFEE2267D2DA5C5E12D9C28112BE3C03EC8667C7950A3BAE1217625F9BBE88DFFC495D27246755732392AE491293EC26D47E1FCD71F51C2EA183554B070345EE82BC942DBA5429E345FEC8B8862A776EF88BB6A96F338CFA7C1020A45527466EA91558FA130FD6BA7093AC751AD6E7325504B067E713E0764E22F3068DAC6E35D3ED9CA4885CCE72EA2AAB24D4BCA92279757DCBF38E05F12BEDA085AB9D842C14EE2F85BAE9ED654497C788ABA982E2D010A0986E01B62BBB35A7DB5AD8338E12D916545393599C12ACDC8B54063D9F128E32C14BD6FF7CA272B2E8B43CA8D29412D821C5B30975225C49DA7D5F94724F0CE75CD68995FBEBC2033FB1C9BEBD543CF33EF440B46A3096B43C4AD3EBA9D13A269FD65158467E65762AE4A42AE8FCABB2A417C87158B27072551DA0C5DC20D00AF3092BF81C522B07F3E78190564DC0E0965FD14B09C4D26ADA51DF951063D5A60AACF10F9229CD5CF990DE31DE1808A5DAD6F67043F98A14446AE0B2E38A8E96FC9AAE6CD0FF86")
#A9539AEAEB99B6C139D7EACA7AC30E766784CC6A6D5296A71D15B9DC61A1D28F
a = hash_elems(h1, h2)
print(a)
#b = str(0)
#print(b.encode("utf-8"))
#seed = hex_to_q("5FCFB59F318CA12CA29ACE93818567CC069737980F68481715ADBD9244499EE4")
#u = Nonces(seed, "constant-chaum-pedersen-proof")[0]
#print(u)

mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)    
#mqttc.on_message = on_message
#mqttc.connect("192.168.12.1", 1883, 60)
#mqttc.message_callback_add("joint_key", on_build_election)
#mqttc.message_callback_add("decryption_share", process_share)

# Send election information. Set retain flag in order for newly subscribed clients to receive the election information.
#message = f"{QUORUM},{NUMBER_OF_GUARDIANS}"
#mqttc.publish("ceremony_details", message, 2, False)
#mqttc.subscribe("joint_key", 2)

#try:
#    mqttc.loop_forever()
#except KeyboardInterrupt:
#    print("Interrupted by user (Ctrl+C)")
#    mqttc.disconnect()
#    sys.exit(0)
#except Exception as e:
#    print(f"An error occurred: {e}")
#    mqttc.disconnect()
#    sys.exit(1)


