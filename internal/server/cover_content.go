// SPDX-License-Identifier: GPL-3.0-or-later

package server

var coverAuthors = [...]string{
	"Ada", "Alex", "Amelia", "Anya", "Ben", "Caleb", "Clara", "Drew",
	"Eli", "Eva", "Felix", "Greta", "Hugo", "Ida", "Iris", "Jamie",
	"June", "Kit", "Leah", "Lena", "Luis", "Mara", "Maya", "Neil",
	"Nina", "Owen", "Rosa", "Sam", "Sofia", "Tess", "Will", "Zoe",
}

var coverPlaceNames = [...]string{
	"Alder", "Amber", "Ash", "Aspen", "Beech", "Birch", "Bluebell", "Briar",
	"Cedar", "Chestnut", "Clover", "Copper", "Cypress", "Elm", "Fern", "Golden",
	"Hazel", "Hawthorn", "Heather", "Holly", "Larch", "Laurel", "Linden", "Maple",
	"Meadow", "Mulberry", "Oak", "Rowan", "Sage", "Silver", "Spruce", "Willow",
}

var coverPlaceTypes = [...]string{
	"Bank", "Bend", "Brook", "Commons", "Corner", "Court", "Crossing", "Dell",
	"Downs", "Field", "Ford", "Glen", "Green", "Grove", "Heights", "Hill",
	"Hollow", "Lane", "Mews", "Mill", "Point", "Rise", "Terrace", "Vale",
}

// Each subject has its own entries and a short list for the next visit.
var coverThemes = [...]coverTheme{
	{
		titles: []string{
			"Walking Notes", "Trail Journal", "Footpath Notes", "Walking Log",
			"Weekend Walks", "Path Notebook", "Hiking Pages", "Walk Diary",
		},
		introductions: []string{
			"I started writing down the walks around %s that I like enough to do twice.",
			"Here are a few short walks from %s and the places I like to stop along the way.",
			"A record of the paths out of %s for those days when the whole afternoon is free.",
			"I use this notebook to remember the turns I missed on my first walks through %s.",
		},
		entries: []coverNote{
			{[7]string{
				"The lower loop after rain", "Drier ground by the stream", "Taking the gravel track",
				"A wet morning on the loop", "The high bank route", "Back along the water", "Where the track dries first",
			}, []string{
				"The stream was loud before I reached the bridge. The gravel along the higher bank was much drier than the short cut across the meadow.",
				"I took the long way back and stopped where the path turns away from the water.",
			}},
			{[7]string{
				"A bench out of the wind", "Lunch inside the trees", "The seat above the track",
				"A sheltered stop", "Sun on the afternoon bench", "Tea off the hillside", "A place for the flask",
			}, []string{
				"There is a bench just inside the trees above the track. It gets sun in the afternoon and there is enough room to set a flask beside you.",
				"The open hillside looked inviting, but I was glad to have my lunch under cover.",
			}},
			{[7]string{
				"An early start", "Before the lane got busy", "Out when the bakery opened",
				"First tracks in the grass", "The quiet bend", "The walk before breakfast", "Home with warm bread",
			}, []string{
				"I set out just as the baker opened and met nobody until the bend. The wet grass showed exactly where a rabbit had crossed the path.",
				"By the walk home the corner was busy again and the bread was still warm.",
			}},
			{[7]string{
				"The lane behind the fields", "Up past the hay barn", "Looking back over the trees",
				"The lane to the gate", "Finding the turn by the post", "A short climb above the fields", "Through the gap in the gate",
			}, []string{
				"The lane climbs gently past the hay barn and ends at a wooden gate. Through the gap beside it you can see the tops of the trees I passed on the way up.",
				"I missed the turn on my first visit. It is opposite the oldest stone post on the lane.",
			}},
			{[7]string{
				"A shorter way home", "The track in fading light", "Leaving the slope at dusk",
				"Walking back before dark", "The last light on the path", "Turning home by the dry track", "Back before the footbridge went dark",
			}, []string{
				"I stayed on the well-drained track when the light started to go. The walk felt like a different place once the last sun left the slope.",
				"Next time I will leave enough daylight to stop at the footbridge again.",
			}},
		},
		listTitles: []string{
			"For the next walk", "In the walking bag", "Before setting out", "Things for the trail",
			"A few things to bring", "Next time on foot", "Things I forgot last time",
		},
		listItems: []string{"Take a spare pair of socks", "Refill the flask", "Pack a small sketchbook",
			"Check the return bus", "Clean the mud from the boots", "Leave time to sit by the water"},
	},
	{
		titles: []string{
			"Kitchen Notebook", "Weeknight Table", "Recipe Book", "Kitchen Journal",
			"Supper Notes", "Home Cooking", "Seasonal Kitchen", "Kitchen Pages",
		},
		introductions: []string{
			"These are the meals I make from memory in my kitchen in %s.",
			"This is where I keep the recipes that earn a second turn on the table in %s.",
			"Notes from a small kitchen in %s, with room for whatever looked good at the market.",
			"I have been keeping notes on what we make for supper in %s.",
		},
		entries: []coverNote{
			{[7]string{
				"Lentils with lemon", "A warm bowl for lunch", "Dressing lentils while warm",
				"Lemon zest and parsley", "A lentil salad that kept well", "Parsley from the market", "A better bowl of leftovers",
			}, []string{
				"I stirred a spoonful of olive oil and some lemon zest into warm lentils. A handful of parsley made the leftovers just as good at lunch.",
				"The bowl kept its shape better when I drained the lentils before dressing them.",
			}},
			{[7]string{
				"A tray of root vegetables", "Making room for the carrots", "Sweet edges on the onions",
				"Two trays instead of one", "Roasted carrots with dill", "Giving the roots more space", "Yogurt for the roasted vegetables",
			}, []string{
				"The carrots needed a little more room to brown. I moved the onions to a second tray and let the edges go dark enough to taste sweet.",
				"A spoonful of plain yogurt with chopped dill was plenty for serving.",
			}},
			{[7]string{
				"Bread for the soup", "Toast in the skillet", "A crisp edge on the bread",
				"Thick slices beside the soup", "The slice with garlic", "Toast while the pot warms", "Bread with a soft middle",
			}, []string{
				"I toasted thick slices in the old skillet while the soup warmed. The crust was crisp and the middle stayed soft enough to tear.",
				"I set one slice aside to rub with a cut clove of garlic.",
			}},
			{[7]string{
				"A pear and oat crumble", "Using up the ripe pears", "Oats over soft fruit",
				"A sweeter batch of pears", "A pinch of salt in the oats", "Warm pears with cream", "Saving the sugar for the topping",
			}, []string{
				"The pears were already sweet, so most of the sugar went into the topping. A pinch of salt made the toasted oats taste much fuller.",
				"We ate it warm with a little cream in the bowls.",
			}},
			{[7]string{
				"The last of the summer herbs", "Mint and basil with tomatoes", "The yellow tomatoes went first",
				"Using the last handful of basil", "A bowl from the herb pots", "What was left in the garden", "A few leaves to save for serving",
			}, []string{
				"I chopped what was left of the basil and mint for a bowl of tomatoes. The small yellow ones were the first to disappear.",
				"Next time I will save a few leaves whole for the top.",
			}},
		},
		listTitles: []string{
			"On the shopping list", "For the next market trip", "Things for the pantry", "What to pick up",
			"Before making supper", "A slip for the market", "Groceries to bring home",
		},
		listItems: []string{"A firm lemon", "Plain yogurt", "A loaf with a good crust",
			"Fresh parsley", "Rolled oats", "Two ripe pears"},
	},
	{
		titles: []string{
			"Bicycle Workshop", "Cycle Repair Notes", "Bike Notebook", "Bicycle Journal",
			"Workshop Diary", "Bike Maintenance Log", "Cycles and Spares", "Bike Shed Notes",
		},
		introductions: []string{
			"Here are the small fixes that keep my old bicycle out on the lanes around %s.",
			"A record of the work I get done in a little bicycle shed in %s.",
			"Most of these started as jobs I put off until the next ride around %s.",
			"I keep this notebook next to the tools I use most often in %s.",
		},
		entries: []coverNote{
			{[7]string{
				"Sorting the little bolts", "A tin for the rack hardware", "Finding the right washers",
				"A label on the small tin", "Clearing the workbench", "Putting the fasteners together", "A better place for the bolts",
			}, []string{
				"I put the rack bolts into a shallow tin instead of leaving them on the bench. Finding the matching washers was easier with everything in daylight.",
				"The lid now has a label so I need not open every tin the next time.",
			}},
			{[7]string{
				"A dry chain", "Road dust on the rollers", "A quieter ride around the block",
				"Wiping off the chain", "One drop for each roller", "A rag for the excess oil", "Taking the dust off the chain",
			}, []string{
				"The chain had collected a film of fine road dust. I wiped it clean and used a drop on each roller, then took the excess off with a rag.",
				"The short ride around the block was much quieter.",
			}},
			{[7]string{
				"Finding the slow puncture", "A bubble in the wash tray", "Glass inside the tire",
				"Marking the leak on the tube", "The tiny hole in the fold", "Checking the tire from inside", "A slow leak at the bench",
			}, []string{
				"A tray of water showed one small bubble at a fold in the tube. I marked the spot before drying it and checked the matching part of the tire.",
				"The culprit was a tiny tip of glass I could only feel from the inside.",
			}},
			{[7]string{
				"Replacing the grips", "Where the old grip wore smooth", "Trying narrower grips",
				"A familiar ride to the park", "New grips on the old bars", "A more comfortable hold", "A quick change at the handlebars",
			}, []string{
				"The left grip had rubbed smooth where my palm sat. I chose a simple pair with a narrow shape and took a familiar route to try them.",
				"My hands felt less tired by the time I turned back at the park.",
			}},
			{[7]string{
				"Sweeping the shed", "Lost levers behind the stand", "A hook for the pump",
				"A clear spot for the wheel stand", "Sorting the corner by the door", "Finding the spare light again", "A clear floor in the shed",
			}, []string{
				"I found two lost tire levers behind the wheel stand. That corner will be easier to keep clear with a small hook for the pump.",
				"The spare light is now in the basket by the door where I can see it.",
			}},
		},
		listTitles: []string{
			"Before the next ride", "Things to check on the bicycle", "A few shed jobs", "On the workbench list",
			"While the bicycle is out", "Jobs before leaving the shed", "A note for the next service",
		},
		listItems: []string{"Charge the front light", "Check the spare tube", "Put a clean rag in the drawer",
			"Make a note of the tire pressure", "Return the hex keys to the case", "Check that the rack is secure"},
	},
	{
		titles: []string{
			"Garden Notebook", "Backyard Journal", "Garden Pages", "Growing Notes",
			"Garden Diary", "Allotment Notes", "Plant Journal", "Garden Calendar",
		},
		introductions: []string{
			"These are notes from the narrow patch I look after in %s.",
			"A little record of the beds and pots behind my place in %s.",
			"I write down what worked in the garden in %s before I forget by spring.",
			"I have been keeping track of which plants do well in my part of %s.",
		},
		entries: []coverNote{
			{[7]string{
				"Room for the seedlings", "A pot for each strong start", "Moving the trays off the sill",
				"Labels before planting", "Seedlings in even light", "Giving the little plants space", "Another set of pots",
			}, []string{
				"The crowded seedlings sat on the sill for a week too long. I gave the strongest ones their own pots and set them where the light was even.",
				"The labels went in first this time. The leaves all look alike at this size.",
			}},
			{[7]string{
				"Water in the morning", "The pot that dries first", "A saucer by the gate",
				"Moving the clay pot into shade", "Checking the water in the saucer", "A dry corner on a warm day", "The morning rounds with the can",
			}, []string{
				"The clay pot by the gate dried faster than the others. A saucer under it made it easier to judge how much water had gone through.",
				"Moving it a little into the shade helped on the warmest afternoon.",
			}},
			{[7]string{
				"Peas along the fence", "Tendrils on the string", "Tucking back the pea stems",
				"Keeping the garden path clear", "A cool patch under the leaves", "String for the climbing peas", "The first shoots at the fence",
			}, []string{
				"The first tendrils found the string without much help. I tucked the longest stems back toward the fence so the path would stay clear.",
				"The soil there still felt cool under the layer of old leaves.",
			}},
			{[7]string{
				"Flowers for a small vase", "Bringing in the bent stems", "A jar on the kitchen table",
				"What opened after the rain", "Cut flowers from the border", "A few stems saved from the rain", "A short jar for the flowers",
			}, []string{
				"I brought in a few stems that had folded in the rain. They stood up well in a short jar and opened on the kitchen table.",
				"This was a better use for the bent stems than trying to prop them up again.",
			}},
			{[7]string{
				"Where the evening light falls", "The sunny end of the bed", "A space next to the rosemary",
				"Watching the fence shadow", "A warmer corner than expected", "The west end in the evening", "Room for one more pot",
			}, []string{
				"The west end of the bed gets more sun than I guessed. I sat there for a while and watched the shadow of the fence move past the rosemary.",
				"There is enough room to try one more low pot beside it.",
			}},
		},
		listTitles: []string{
			"At the potting bench", "Jobs for the beds and pots", "To do in the garden", "The next jobs outside",
			"Things for the seedlings", "Before going back to the beds", "A few jobs by the shed",
		},
		listItems: []string{"Wash the empty trays", "Bring the soft twine", "Set aside the smaller pots",
			"Make labels for the herbs", "Move the watering can by the steps", "Look for the missing trowel"},
	},
	{
		titles: []string{
			"Bird Notebook", "Birdwatching Diary", "Bird Notes", "Birding Journal",
			"Bird Walks", "Birdwatching Pages", "Backyard Birds", "Bird Sightings",
		},
		introductions: []string{
			"A notebook for the birds I see on the same few walks around %s.",
			"Most of these sightings in %s came from waiting still for another minute.",
			"I am keeping a record of which birds turn up in %s through the seasons.",
			"These are the calls and small movements I notice on the quiet paths in %s.",
		},
		entries: []coverNote{
			{[7]string{
				"A wren in the hedge", "A call under the brambles", "Watching the base of the hedge",
				"A pause between the leaves", "The bird at the thin end of the hedge", "First a call and then a glimpse", "The wren along the lane",
			}, []string{
				"I heard the call several times before seeing the bird. It worked along the base of the hedge and paused just where the brambles thinned.",
				"The place looked empty again as soon as it stepped back into the leaves.",
			}},
			{[7]string{
				"Swallows above the field", "Watching from the gate", "Four above the open field",
				"Swallows just before the rain", "A low flight over wet grass", "Following them after the shower", "The birds at the far end of the field",
			}, []string{
				"The swallows stayed low over the grass before the rain and climbed after it passed. Watching from the gate was easier than trying to follow them down the road.",
				"I counted four by watching them return to the open end of the field.",
			}},
			{[7]string{
				"Ducks at the quiet end", "Two birds behind the reeds", "Waiting by the sheltered pond",
				"Where the pond barely moves", "Ducks drifting out from cover", "The far corner of the water", "A quiet look through binoculars",
			}, []string{
				"The pond looked empty from the path until I reached the reeds. Two ducks were tucked into the sheltered corner where the water hardly moved.",
				"I kept the binoculars low and waited for them to drift out on their own.",
			}},
			{[7]string{
				"The morning chorus", "A call before sunrise", "A blackbird on the fence",
				"Listening from the back step", "The voices that joined at dawn", "A few songs I recognized", "Standing still before breakfast",
			}, []string{
				"A blackbird sang from the top of the fence well before the sun was up. The other calls picked up slowly while I stood by the back step.",
				"I recognized more of the familiar songs when I stopped trying to write at the same time.",
			}},
			{[7]string{
				"A winter visitor", "A robin by the rake", "The sheltered branch",
				"A bird in the undisturbed leaves", "A regular at the border", "What came out when I stopped raking", "The robin’s quiet corner",
			}, []string{
				"The robin appeared as soon as I put down the rake. It looked through the leaves by the border before hopping back to the sheltered branch.",
				"I have started leaving that little corner undisturbed.",
			}},
		},
		listTitles: []string{
			"Places to watch next", "Where to take the binoculars", "For the next bird walk", "Things to look and listen for",
			"Stops worth another visit", "The next places to sit quietly", "Paths with a good view of birds",
		},
		listItems: []string{"The reeds by the small pond", "The gate at the open field", "The back step before breakfast",
			"The quiet end of the lane", "The old hedge after rain", "The low branches by the wall"},
	},
	{
		titles: []string{
			"Night Sky Notes", "Stargazing Journal", "Sky Watch", "Backyard Astronomy",
			"Evening Sky Diary", "Stargazing Notebook", "Night Watch Notes", "Observing Journal",
		},
		introductions: []string{
			"Things I could see from the yard in %s when the clouds finally cleared.",
			"Notes from a chair outside in %s and the patience to sit there a bit longer.",
			"I keep a short record of clear nights over %s and where I looked first.",
			"These sketches and notes come from evenings spent outside in %s.",
		},
		entries: []coverNote{
			{[7]string{
				"A thin crescent", "The moon above the roofs", "The faint round edge",
				"A crescent from the back step", "Finding the moon again", "Just enough light at dusk", "Earthshine over the houses",
			}, []string{
				"The moon was just above the roofs at dusk. After a few minutes I could make out the faint round edge on the dark side.",
				"I marked the spot from the back step so I could look there again the next evening.",
			}},
			{[7]string{
				"Waiting for dark", "After the garden light went out", "Stars above the tree",
				"Away from the kitchen window", "Giving my eyes a minute", "More stars than I expected", "The patch that looked empty",
			}, []string{
				"I turned off the garden light and let my eyes settle. What had looked like an empty patch above the tree slowly filled with faint stars.",
				"A few minutes away from the bright kitchen window made a bigger difference than I expected.",
			}},
			{[7]string{
				"A steadier view", "Resting on the back of a chair", "Shadows in the craters",
				"Holding the binoculars still", "A chair at the back step", "The moon through a steadier pair", "A better look at the craters",
			}, []string{
				"I rested my elbows on the back of a chair while looking at the moon through binoculars. The shadows around the larger craters were much easier to make out.",
				"The chair will stay by the step for the next clear night.",
			}},
			{[7]string{
				"The gap in the clouds", "Stars above the chimney", "Following a strip of clear sky",
				"A short break in the cloud", "Before the stars disappeared again", "The view that lasted a minute", "Binoculars by the door",
			}, []string{
				"The sky cleared in a narrow strip above the neighbor’s chimney. I followed that opening until the edge blurred and the stars disappeared again.",
				"The session was short, but I remembered why I leave the binoculars by the door.",
			}},
			{[7]string{
				"Sketching the bright stars", "A few pencil marks after dark", "Starting with the brightest points",
				"A pattern worth drawing", "The direction on the sketch", "A map that fits in the notebook", "Drawing the faint stars last",
			}, []string{
				"I drew the easiest stars to find first and added the faint ones around them. The little sketch was more useful later than a long list of directions.",
				"I wrote down which way I was facing so the pattern would make sense in the morning.",
			}},
		},
		listTitles: []string{
			"For a clear evening", "What to take outside", "Things to do after dusk", "When the sky clears again",
			"Before the stars come out", "At the back step after dark", "Ready for a night outside",
		},
		listItems: []string{"Find the soft pencil", "Bring out a low chair", "Set a spare layer by the door",
			"Check the view above the roofs", "Let the eyes adjust", "Wipe dew off the binocular case"},
	},
	{
		titles: []string{
			"Reading Notes", "Bookshelf Journal", "Book Diary", "Shelf Notes",
			"Reading Room", "Book Notebook", "Library Notes", "Pages and Margins",
		},
		introductions: []string{
			"A record of good reading days in %s and what I kept thinking about afterward.",
			"Short notes from the shelf, the library in %s, and the stack beside my chair.",
			"I began this reading notebook in %s to remember what I liked before I forgot the plot.",
			"Here are a few books I brought home and sat down with in %s.",
		},
		entries: []coverNote{
			{[7]string{
				"A book for the train", "The novel in my coat pocket", "Finishing on the platform",
				"A slim book for the ride", "Reading past the brick walls", "The chapter I meant to save", "A good choice for the journey",
			}, []string{
				"I picked a slim novel that would fit in my coat pocket. It was an excellent choice for the long stretch where the view was all brick walls.",
				"I finished the last chapter on the platform instead of saving it for the ride home.",
			}},
			{[7]string{
				"Rereading an old favorite", "A folded receipt for a bookmark", "The chapters I remembered wrong",
				"Back to a familiar book", "What stayed between the pages", "The book I put back again", "Finding my old place",
			}, []string{
				"The middle chapters were funnier than I remembered. My old bookmark was still there, just a receipt folded almost white at the corners.",
				"I left it in the same place when I put the book back.",
			}},
			{[7]string{
				"A useful index", "One question in a book of essays", "Three other essays to read",
				"Looking up a small detail", "Moving the book near the table", "Reading from the index", "An afternoon with the essays",
			}, []string{
				"I opened the book of essays to settle a small question and found three other things I wanted to read. The index did most of the work.",
				"The book has moved to the shelf nearest the table.",
			}},
			{[7]string{
				"Clearing the nightstand", "One book beside the lamp", "The books I took back",
				"Making room for a glass of water", "Picking up an unfinished book", "A smaller reading stack", "The nightstand in daylight",
			}, []string{
				"I returned two library books and moved the unfinished ones where I would see them in daylight. It was easier to start again with only one book by the lamp.",
				"The empty space makes a surprisingly good place for a glass of water.",
			}},
			{[7]string{
				"The quiet shelf at the library", "A collection of short stories", "The shelf away from the door",
				"A book I would have passed by", "A tip from the librarian", "Looking past the cover", "What I found on the far shelf",
			}, []string{
				"The display near the door was busy, so I tried the far shelf of short stories. I found a collection I would never have chosen from the cover alone.",
				"The librarian remembered the author and pointed out a second book to try.",
			}},
		},
		listTitles: []string{
			"For the next library visit", "Before I go to the library", "With the library books", "Things to read or return",
			"On a slip inside the book bag", "A few notes for the shelves", "For an afternoon at the library",
		},
		listItems: []string{"Return the essay collection", "Bring the cloth book bag", "Look for the short stories",
			"Note where the travel books moved", "Renew the hardback", "Try a book from the lower shelf"},
	},
	{
		titles: []string{
			"Photo Journal", "Camera Notes", "Photography Diary", "Photo Notebook",
			"Pictures and Light", "Camera Walks", "Light and Shade", "Photo Log",
		},
		introductions: []string{
			"Notes about light and the small walks I take with a camera around %s.",
			"I write down where I stood in %s and what the light was doing when I took a picture.",
			"A record of little scenes in %s that seemed worth stopping for.",
			"I made these notes on familiar streets in %s while trying a few different views.",
		},
		entries: []coverNote{
			{[7]string{
				"A wet pavement at dusk", "Shop light on the paving stones", "Waiting for the crossing to clear",
				"A little blue left in the sky", "The earlier frame after rain", "Taking the picture from across the road", "Dusk reflected on the pavement",
			}, []string{
				"The shop light spread across the paving stones after rain. I waited for a gap in the foot traffic, then took the picture from the far side of the crossing.",
				"The color was better in the earlier frame while a bit of blue remained in the sky.",
			}},
			{[7]string{
				"The window at breakfast", "The cup in the morning light", "Moving the chair out of the frame",
				"Light at the edge of the table", "A window-lit still life", "Leaving the tablecloth folded", "A simpler picture at breakfast",
			}, []string{
				"The light from the window fell right across the cup and stopped at the edge of the table. I moved the chair back a little to keep its shadow out of the frame.",
				"The picture was simplest when I left the tablecloth folded away.",
			}},
			{[7]string{
				"Two walks past the same wall", "Later light on the stones", "The wall at noon and afterward",
				"Watching the mortar in low light", "Grass against the old stones", "The shadows that appeared later", "Making a note of the afternoon light",
			}, []string{
				"The wall by the field looked flat at noon. Later the uneven stones cast little shadows and the dry grass stood out from the mortar.",
				"I have written down the time so I can try again when the light is lower.",
			}},
			{[7]string{
				"A small set of prints", "Laying the pictures in a row", "More room around the subject",
				"Choosing prints side by side", "The frames I liked best", "Trying a wider view next time", "What changed when I saw them together",
			}, []string{
				"I set the prints in a row rather than judging them one at a time. The ones I liked best all had a little room around the main subject.",
				"I will try a wider frame on the next walk through town.",
			}},
			{[7]string{
				"Fog over the fence", "A sharp post in a gray field", "The fence before the fog lifted",
				"Getting down close to the grass", "Framing the nearest post", "What the fog left visible", "The field that cleared on the way back",
			}, []string{
				"The nearest fence post was sharp and everything behind it disappeared into gray. I moved low enough to leave the grass in the bottom of the frame.",
				"By the time I turned back, the field was clear again.",
			}},
		},
		listTitles: []string{
			"Ideas for another walk", "Things to photograph next", "For a walk with the camera", "Places to try a picture",
			"Views to come back to", "Notes for the next roll", "A few more frames to try",
		},
		listItems: []string{"A doorway in the morning light", "The corner shop after rain", "The shadows under the steps",
			"A still life on the windowsill", "The wall when the sun is low", "The path on a foggy day"},
	},
	{
		titles: []string{
			"Coffee Notebook", "Coffee Journal", "Brew Notes", "Morning Coffee",
			"Coffee Diary", "Kitchen Brew Log", "Coffee Pages", "Home Coffee Notes",
		},
		introductions: []string{
			"These are the little changes to the morning cup I make in %s.",
			"I keep this notebook by the kettle in %s so the good brews are easy to repeat.",
			"An occasional record of beans, water, and what went well at breakfast in %s.",
			"I started these notes in %s after a friend asked how I made the coffee.",
		},
		entries: []coverNote{
			{[7]string{
				"A coarser grind", "Turning the grinder one mark", "A sweeter cup as it cooled",
				"Adjusting after a dry-tasting cup", "Writing down the new setting", "A small change at the grinder", "Tasting the two grinds",
			}, []string{
				"The previous cup tasted a bit dry. I turned the grinder one mark coarser and found the next cup sweeter as it cooled.",
				"I wrote down the setting before cleaning the counter.",
			}},
			{[7]string{
				"Warming the small mug", "Hot water in the heavy mug", "Keeping the winter cup warm",
				"Warming the mug while I weigh the beans", "Choosing between two cups", "A warmer start with the kettle", "A small change on cold mornings",
			}, []string{
				"The heavy mug cools the coffee quickly on winter mornings. I filled it with hot water while I weighed the beans and found the change worth the extra moment.",
				"The lighter cup still works better when I want to drink right away.",
			}},
			{[7]string{
				"A different filter", "The first rinse of the new paper", "Two cups with the same steps",
				"Rinsing before adding the grounds", "Letting the filter drain", "Where the paper smell went", "Trying the new papers",
			}, []string{
				"I rinsed the new filter and let the water drain before adding the grounds. The paper smell disappeared after that first rinse.",
				"I kept the other steps the same so the cups would be easy to compare.",
			}},
			{[7]string{
				"Saving the last handful", "Enough beans for one small pot", "The last cup from the bag",
				"Measuring with the little jug", "Brewing a smaller batch", "Finishing the bag before opening another", "A last pot from the old beans",
			}, []string{
				"There was just enough in the bag for one last small pot. I brewed a little less than usual and used the small jug instead of guessing.",
				"It was a pleasant way to finish the bag before opening the next one.",
			}},
			{[7]string{
				"Coffee with cake", "A lighter cup in the evening", "The cup beside the walnut cake",
				"An afternoon with the small pot", "Waiting a minute before drinking", "A pot to keep for later", "A slice of cake with the brew",
			}, []string{
				"I made the evening cup a little lighter and served it with a slice of walnut cake. The coffee tasted better once it had sat in the cup for a minute.",
				"I am keeping the little pot for afternoons like this.",
			}},
		},
		listTitles: []string{
			"Beside the kettle", "Before making another pot", "On the coffee shelf", "For the next morning cup",
			"Notes for the next brew", "In the kitchen before breakfast", "A few reminders for the grinder",
		},
		listItems: []string{"Refill the filter tin", "Mark the grinder setting", "Rinse the small pot",
			"Set out the lighter cup", "Record the next bag’s opening date", "Leave the scale on the shelf"},
	},
	{
		titles: []string{
			"Local History Notes", "Town Notebook", "Neighborhood Journal", "Street History",
			"Local Archive Notes", "Town History Diary", "Notes on the Old Town", "Local History Journal",
		},
		introductions: []string{
			"Here are small things I have noticed in old maps of %s and on familiar streets.",
			"A record of places in %s worth a second look on the walk home from the library.",
			"Loose notes on the corners of %s that keep turning up in old photographs.",
			"I use this page to keep track of small questions about the streets in %s.",
		},
		entries: []coverNote{
			{[7]string{
				"The road on the older map", "A lane behind the houses", "The bend in two maps",
				"Following the low wall", "The short line on the map", "An unnamed lane in the drawer", "Tracing an older way through town",
			}, []string{
				"The old map shows a lane cutting behind the houses before the main road bends. Part of the line still makes sense if you follow the low wall.",
				"The next map in the drawer shows the bend but leaves that lane unnamed.",
			}},
			{[7]string{
				"A photograph of the market", "The same window above the shop", "Looking up at the corner window",
				"Finding a familiar building in a print", "Where the awning used to be", "A closer view from the old street", "The window that stayed",
			}, []string{
				"I recognized the high window above the corner shop in a photograph at the library. The awning is gone, but the small window is still easy to spot from the crossing.",
				"The photograph was taken from much closer to the street than I first guessed.",
			}},
			{[7]string{
				"A date above the door", "Reading the stone from the pavement", "Two digits in the afternoon light",
				"The inscription across the road", "Looking up the building number", "A date I could almost read", "Turning back for a better angle",
			}, []string{
				"The date cut into the stone is hard to read from the opposite pavement. At the right angle in the afternoon I could see the last two digits clearly.",
				"I will check the building list next time I go to the library.",
			}},
			{[7]string{
				"Where the wall changes", "Brick beside the old stone", "A sketch of the join",
				"A possible repair by the gate", "Rough stone on the lane", "The corner that catches the light", "A detail too small for the map",
			}, []string{
				"The wall by the lane switches from rough stone to brick beside a gate. It might mark an old repair, but the map is too small to be sure.",
				"I sketched the join and noted which side catches the morning light.",
			}},
			{[7]string{
				"Two names for the same corner", "Looking through the old directories", "The address that did not change",
				"The shop between familiar neighbors", "Comparing two directory listings", "The missing year on the shelf", "A different name beside the same number",
			}, []string{
				"I found two different names in the old directories for the shop at the corner. The address has the same number and sits between the same two neighbors in both lists.",
				"There is another directory from the intervening year that I have yet to check.",
			}},
		},
		listTitles: []string{
			"To look up next", "Questions for the archive", "Back at the library", "Things to check on the old maps",
			"Still looking for", "On the next walk through town", "Places to look a little closer",
		},
		listItems: []string{"The next edition of the street map", "The old shop directories", "A clear photo of the corner window",
			"The building list at the library", "The names on the market photographs", "The lane marked beside the field"},
	},
}
