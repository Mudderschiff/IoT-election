import json
from datetime import datetime, timedelta

from electionguard import SpecVersion, ElectionType, GeopoliticalUnit, ReportingUnitType, Party, Candidate, BallotStyle, \
    SelectionDescription, VoteVariationType, \
    ContestDescription
from electionguard_tools.helpers.election_builder import ElectionBuilder
from electionguard.manifest import Manifest
import paho.mqtt.client as mqtt

manifest: Manifest
NUMBER_OF_GUARDIANS = 2
QUORUM = 2
sequence_number = 0

def on_message(mosq, obj, msg):
    # This callback will be called for messages that we receive that do not
    # match any patterns defined in topic specific callbacks, i.e. in this case
    # those messages that do not have topics $SYS/broker/messages/# nor
    # $SYS/broker/bytes/#
    print(msg.topic + " " + str(msg.qos) + " " + str(msg.payload))

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

print("Manifest is Valid?:", manifest.is_valid())

election_builder = ElectionBuilder(
    NUMBER_OF_GUARDIANS, QUORUM, manifest
)
print("Created with number_of_guardians:", NUMBER_OF_GUARDIANS)
print("Created with quorum:", QUORUM)

#Step 1 Key ceremony, one is choosen as mediator
mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
# Add message callbacks that will only trigger on a specific subscription match.
#.message_callback_add("$SYS/broker/bytes/#", on_message_bytes)
mqttc.on_message = on_message
mqttc.connect("192.168.12.1", 1883, 60)
# Send election information. Set retain flag in order for newly subscribed clients to receive the election information.
message = f"{QUORUM},{NUMBER_OF_GUARDIANS}"
mqttc.publish("ceremony_details", message, 2, True)
mqttc.loop_forever()


