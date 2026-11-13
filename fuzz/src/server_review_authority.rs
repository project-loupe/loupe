//! Phase recipe support against the B4 authority contract's "Supported
//! recipes" section and SPEC-02 §2. The oracle is a table of the permitted
//! rows; every context that matches no row must be denied.
use loupe_server::fuzz_support::{
	review_recipe_supported, Access, CampaignRecipe, GenerationFacts, GenerationState, RecipeKind,
	SupportFacts,
};

use crate::utils::test_logger;

const RECIPES: [RecipeKind; 7] = [
	RecipeKind::Bootstrap,
	RecipeKind::Coverage,
	RecipeKind::Incremental,
	RecipeKind::Reconciliation,
	RecipeKind::Corroboration,
	RecipeKind::Drilldown,
	RecipeKind::Verify,
];
const CAMPAIGNS: [CampaignRecipe; 4] = [
	CampaignRecipe::Bootstrap,
	CampaignRecipe::Incremental,
	CampaignRecipe::Reconciliation,
	CampaignRecipe::Corroboration,
];
const STATES: [GenerationState; 3] =
	[GenerationState::Building, GenerationState::Active, GenerationState::Retired];
const ACCESSES: [Access; 4] =
	[Access::LeaseControl, Access::Checkout, Access::PreparedHost, Access::Domain];

/// Generation pattern of one permitted row.
#[derive(Clone, Copy)]
enum Gen {
	/// No generation yet: unpinned setup.
	None,
	/// Same-commit active generation, any predecessor.
	Active,
	/// Same-commit predecessor-free building generation (initial bootstrap).
	InitialBuilding,
}

struct Row {
	recipes: &'static [RecipeKind],
	campaigns: &'static [CampaignRecipe],
	generation: Gen,
	/// Only consulted for unpinned setup rows; pinned rows leave access and
	/// head checks to storage.
	unpinned_checkout_only: bool,
}

const SUPPORTED_CAMPAIGNS: &[CampaignRecipe] =
	&[CampaignRecipe::Bootstrap, CampaignRecipe::Incremental];
const CHILDREN: &[RecipeKind] = &[RecipeKind::Drilldown, RecipeKind::Verify];

/// "Bootstrap accepts unpinned Checkout and predecessor-free building setup.
/// Coverage requires active generation. Incremental accepts unpinned Checkout
/// only, then same-commit active generation; successors, reconciliation and
/// corroboration deny domain and setup access. Child phases require [...]
/// active ready generation, or initial bootstrap-building ready generation.
/// Unsupported campaign recipes cannot gain domain access via a child recipe."
const TABLE: &[Row] = &[
	Row {
		recipes: &[RecipeKind::Bootstrap],
		campaigns: &[CampaignRecipe::Bootstrap],
		generation: Gen::None,
		unpinned_checkout_only: true,
	},
	Row {
		recipes: &[RecipeKind::Bootstrap],
		campaigns: &[CampaignRecipe::Bootstrap],
		generation: Gen::InitialBuilding,
		unpinned_checkout_only: false,
	},
	Row {
		recipes: &[RecipeKind::Coverage],
		campaigns: SUPPORTED_CAMPAIGNS,
		generation: Gen::Active,
		unpinned_checkout_only: false,
	},
	Row {
		recipes: &[RecipeKind::Incremental],
		campaigns: &[CampaignRecipe::Incremental],
		generation: Gen::None,
		unpinned_checkout_only: true,
	},
	Row {
		recipes: &[RecipeKind::Incremental],
		campaigns: &[CampaignRecipe::Incremental],
		generation: Gen::Active,
		unpinned_checkout_only: false,
	},
	Row {
		recipes: CHILDREN,
		campaigns: SUPPORTED_CAMPAIGNS,
		generation: Gen::Active,
		unpinned_checkout_only: false,
	},
	Row {
		recipes: CHILDREN,
		campaigns: &[CampaignRecipe::Bootstrap],
		generation: Gen::InitialBuilding,
		unpinned_checkout_only: false,
	},
];

fn row_matches(row: &Row, recipe: RecipeKind, facts: &SupportFacts) -> bool {
	let generation = match (row.generation, facts.generation) {
		(Gen::None, None) => true,
		(Gen::Active, Some(g)) => g.commits_equal && g.state == GenerationState::Active,
		(Gen::InitialBuilding, Some(g)) => {
			g.commits_equal && g.state == GenerationState::Building && !g.predecessor_present
		},
		_ => false,
	};
	let access =
		!row.unpinned_checkout_only || (facts.access == Access::Checkout && !facts.head_present);
	row.recipes.contains(&recipe) && row.campaigns.contains(&facts.campaign) && generation && access
}

pub fn spec_supported(recipe: RecipeKind, facts: &SupportFacts) -> bool {
	TABLE.iter().any(|row| row_matches(row, recipe, facts))
}

fn pick<T: Copy>(items: &[T], byte: u8) -> T {
	items[usize::from(byte) % items.len()]
}

pub fn do_test(data: &[u8]) {
	for chunk in data.as_chunks::<5>().0 {
		let recipe = pick(&RECIPES, chunk[0]);
		let generation = (chunk[2] & 1 == 1).then(|| GenerationFacts {
			state: pick(&STATES, chunk[3]),
			predecessor_present: chunk[2] & 2 != 0,
			commits_equal: chunk[2] & 4 != 0,
		});
		let facts = SupportFacts {
			campaign: pick(&CAMPAIGNS, chunk[1]),
			generation,
			head_present: chunk[2] & 8 != 0,
			access: pick(&ACCESSES, chunk[4]),
		};
		let expected = spec_supported(recipe, &facts);
		assert_eq!(
			review_recipe_supported(recipe, facts),
			expected,
			"recipe support differs from the authority contract for {recipe:?} {facts:?}"
		);
	}
}

pub fn server_review_authority_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn server_review_authority_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller guarantees a valid readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
