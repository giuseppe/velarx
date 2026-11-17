//! Custom type, field and parameter definitions for Varlink IDL.

use core::fmt;

use super::{Comment, List, Type, TypeRef};

/// A field in a custom type or method parameter.
#[derive(Debug, Clone, Eq)]
pub struct Field<'a> {
    /// The name of the field.
    name: &'a str,
    /// The type of the field.
    ty: TypeRef<'a>,
    /// Comments associated with this field.
    comments: List<'a, Comment<'a>>,
}

/// Type alias for method parameters, which have the same structure as fields.
pub type Parameter<'a> = Field<'a>;

impl<'a> Field<'a> {
    /// Creates a new field with the given name, borrowed type, and comments.
    pub const fn new(name: &'a str, ty: &'a Type<'a>, comments: &'a [&'a Comment<'a>]) -> Self {
        Self {
            name,
            ty: TypeRef::new(ty),
            comments: List::Borrowed(comments),
        }
    }

    /// Same as `new` but takes `ty` by value.
    /// Creates a new field with the given name, owned type, and comments.
    pub fn new_owned(name: &'a str, ty: Type<'a>, comments: alloc::vec::Vec<Comment<'a>>) -> Self {
        Self {
            name,
            ty: TypeRef::new_owned(ty),
            comments: List::from(comments),
        }
    }

    /// Returns the name of the field.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Returns the type of the field.
    pub const fn ty(&self) -> &Type<'a> {
        self.ty.inner()
    }

    /// Returns the comments associated with this field.
    pub fn comments(&self) -> impl Iterator<Item = &Comment<'a>> {
        self.comments.iter()
    }
}

impl<'a> fmt::Display for Field<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Comments first
        for comment in self.comments.iter() {
            writeln!(f, "{comment}")?;
        }
        write!(f, "{}: {}", self.name, self.ty)
    }
}

/// Write `fields` between parentheses.  When any of them has comments, or a
/// type of its own that takes several lines (an object or an enum with
/// comments), each goes on a line of its own, tab indented, with its
/// comments on the lines above it (as the variants of an enum are written);
/// else on one line.
pub(crate) fn write_fields<'a>(
    f: &mut fmt::Formatter<'_>,
    fields: &List<'a, Field<'a>>,
) -> fmt::Result {
    use alloc::string::ToString;

    let types: alloc::vec::Vec<_> = fields.iter().map(|field| field.ty.to_string()).collect();
    write!(f, "(")?;
    let several = fields.iter().any(|field| field.comments.iter().next().is_some())
        || types.iter().any(|ty| ty.contains('\n'));
    if several {
        writeln!(f)?;
        let last = types.len().saturating_sub(1);
        for (i, (field, ty)) in fields.iter().zip(&types).enumerate() {
            for comment in field.comments.iter() {
                writeln!(f, "\t{comment}")?;
            }
            let comma = if i == last { "" } else { "," };
            // (a type of several lines goes one tab further in)
            writeln!(f, "\t{}: {}{comma}", field.name, ty.replace('\n', "\n\t"))?;
        }
    } else {
        for (i, (field, ty)) in fields.iter().zip(&types).enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}: {ty}", field.name)?;
        }
    }
    write!(f, ")")
}

impl<'a> PartialEq for Field<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.ty == other.ty
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Type;

    #[test]
    fn field_creation() {
        let field = Field::new("age", &Type::Int, &[]);
        assert_eq!(field.name(), "age");
        assert_eq!(field.ty(), &Type::Int);
    }

    #[test]
    fn parameter_alias() {
        let param: Parameter<'_> = Field::new("input", &Type::String, &[]);
        assert_eq!(param.name(), "input");
        assert_eq!(param.ty(), &Type::String);
    }

    #[test]
    fn display_with_comments() {
        use crate::Comment;
        use core::fmt::Write;

        let comment1 = Comment::new("User's email address");
        let comment2 = Comment::new("Must be valid format");
        let comments = [&comment1, &comment2];

        let field = Field::new("email", &Type::String, &comments);
        let mut displayed = String::new();
        write!(&mut displayed, "{}", field).unwrap();
        assert_eq!(
            displayed,
            "# User's email address\n# Must be valid format\nemail: string"
        );
    }

    /// Each comment of a list of fields is directly above its own field.
    #[test]
    fn fields_with_comments_are_one_per_line() {
        use crate::Comment;

        struct Fields<'a>(List<'a, Field<'a>>);
        impl core::fmt::Display for Fields<'_> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write_fields(f, &self.0)
            }
        }

        let name = Field::new_owned("name", Type::String, alloc::vec![]);
        let age = Field::new_owned(
            "age",
            Type::Int,
            alloc::vec![Comment::new("Years"), Comment::new("or less")],
        );
        let none = alloc::vec![name.clone()];
        assert_eq!(alloc::format!("{}", Fields(none.into())), "(name: string)");
        assert_eq!(alloc::format!("{}", Fields(alloc::vec![].into())), "()");
        let inner = Type::Object(alloc::vec![age.clone()].into());
        let nested = alloc::vec![Field::new_owned("inner", inner, alloc::vec![])];
        assert_eq!(
            alloc::format!("{}", Fields(nested.into())),
            "(\n\tinner: (\n\t\t# Years\n\t\t# or less\n\t\tage: int\n\t)\n)"
        );
        let both = alloc::vec![name, age];
        assert_eq!(
            alloc::format!("{}", Fields(both.into())),
            "(\n\tname: string,\n\t# Years\n\t# or less\n\tage: int\n)"
        );
    }
}
