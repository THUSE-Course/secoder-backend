use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "group_members")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub group_code_name: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub student_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
