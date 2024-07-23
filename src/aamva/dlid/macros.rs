macro_rules! data_elements_enum {
	($(#[$enum_meta:meta])* $vis:vis enum $enum_id:ident { $($(#[$meta:meta])* $id:ident : $tag:literal),* }) => {
		$(#[$enum_meta])*
		#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
		$vis enum $enum_id {
			$($(#[$meta])* $id),*
		}

		impl $enum_id {
			pub const COUNT: usize = $crate::aamva::dlid::data_elements_enum!(@count $($id,)*);
			pub const LIST: [Self; Self::COUNT] = [$(Self::$id),*];

			pub fn from_id(id: &[u8; 3]) -> Option<Self> {
				match id {
					$($tag => Some(Self::$id),)*
					_ => None
				}
			}

			pub fn id(&self) -> &'static [u8; 3] {
				match self {
					$(Self::$id => $tag),*
				}
			}
		}

		impl $enum_id {
			pub fn string_id(&self) -> &str {
				unsafe { std::str::from_utf8_unchecked(self.id()) }
			}
		}
	};
	(@count $a:ident, $($rest:ident,)*) => {
		1usize + $crate::aamva::dlid::data_elements_enum!(@count $($rest,)*)
	};
	(@count) => {
		0usize
	}
}

macro_rules! mandatory_data_elements {
	($(#[$enum_meta:meta])* $vis:vis enum $enum_id:ident, struct $struct_id:ident ($partial_id:ident) { $($(#[$meta:meta])* $field:ident : $ty:ident => $id:ident : $tag:literal),* }) => {
		$crate::aamva::dlid::data_elements_enum!($(#[$enum_meta])* $vis enum $enum_id { $($(#[$meta])* $id : $tag),* });

		#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
		$vis struct $struct_id {
			$($(#[$meta])* pub $field: Vec<u8>),*
		}

		impl $struct_id {
			pub fn new_with<'a>(mut f: impl FnMut($enum_id) -> std::borrow::Cow<'a, [u8]>) -> Self {
				Self {
					$($field: f($enum_id::$id).into_owned()),*
				}
			}

			pub fn get(&self, element: $enum_id) -> &[u8] {
				match element {
					$($enum_id::$id => self.$field.as_slice()),*
				}
			}

			pub fn set(&mut self, element: $enum_id, value: Vec<u8>) {
				match element {
					$($enum_id::$id => { self.$field = value }),*
				}
			}

			pub fn iter(&self) -> impl Iterator<Item = ($enum_id, &[u8])> {
				[$(($enum_id::$id, self.$field.as_slice())),*].into_iter()
			}
		}

		#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
		$vis struct $partial_id {
			$($(#[$meta])* pub $field: Option<Vec<u8>>),*
		}

		impl $partial_id {
			pub fn new() -> Self {
				Self::default()
			}

			pub fn get(&self, element: $enum_id) -> Option<&[u8]> {
				match element {
					$($enum_id::$id => self.$field.as_ref().map(|v| v.as_slice())),*
				}
			}

			pub fn set(&mut self, element: $enum_id, value: Vec<u8>) {
				match element {
					$($enum_id::$id => { self.$field = Some(value) }),*
				}
			}

			pub fn build(self) -> Result<$struct_id, $crate::aamva::dlid::MissingDataElement<$enum_id>> {
				Ok($struct_id {
					$($field: self.$field.ok_or($crate::aamva::dlid::MissingDataElement($enum_id::$id))?),*
				})
			}
		}
	}
}

macro_rules! optional_data_elements {
	($(#[$enum_meta:meta])* $vis:vis enum $enum_id:ident, struct $struct_id:ident { $($(#[$meta:meta])* $field:ident : $ty:ident => $id:ident : $tag:literal),* }) => {
		$crate::aamva::dlid::data_elements_enum!($(#[$enum_meta])* $vis enum $enum_id { $($(#[$meta])* $id : $tag),* });

		#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
		$vis struct $struct_id {
			$($(#[$meta])* pub $field: Option<Vec<u8>>),*
		}

		impl $struct_id {
			pub fn new() -> Self {
				Self::default()
			}

			pub fn is_empty(&self) -> bool {
				$(
					if self.$field.is_some() {
						return false
					}
				)*

				true
			}

			pub fn len(&self) -> usize {
				let mut result = 0;

				$(
					if self.$field.is_some() {
						result += 1
					}
				)*

				result
			}

			pub fn get(&self, element: $enum_id) -> Option<&[u8]> {
				match element {
					$($enum_id::$id => self.$field.as_ref().map(|v| v.as_slice())),*
				}
			}

			pub fn set(&mut self, element: $enum_id, value: Option<Vec<u8>>) {
				match element {
					$($enum_id::$id => { self.$field = value }),*
				}
			}

			pub fn iter(&self) -> impl Iterator<Item = ($enum_id, &[u8])> {
				[$(
					self.$field
						.as_ref()
						.map(|value| ($enum_id::$id, value.as_slice()))
				),*].into_iter().flatten()
			}
		}
	}
}

pub(crate) use data_elements_enum;
pub(crate) use mandatory_data_elements;
pub(crate) use optional_data_elements;
