class APIFeature {
  constructor(query, querySting) {
    this.query = query;
    this.querySting = querySting;
  }

  filter() {
    const queryObject = { ...this.querySting };
    const excludedFields = ['page', 'sort', 'limit', 'fields'];
    excludedFields.forEach(el => delete queryObject[el]);

    let queryStr = JSON.stringify(queryObject);
    queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, match => `$${match}`);

    this.query = this.query.find(JSON.parse(queryStr));
    return this;
  }

  sort() {
    if (this.querySting.sort) {
      const sortBy = this.querySting.sort.split(',').join(' ');
      this.query = this.query.sort(sortBy);
    } else {
      this.query = this.query.sort('-createdAt');
    }
    return this;
  }

  limitFields() {
    if (this.querySting.fields) {
      const selectedFields = this.querySting.fields.split(',').join(' ');
      this.query = this.query.select(selectedFields);
    }
    return this;
  }

  paginate() {
    const page = this.querySting.page * 1 || 1;
    const limit = this.querySting.limit * 1 || 100;
    const skip = (page - 1) * limit;
    // page=2&limit=10, 1-10, page 1, 11-20, page 2, 21-30 page 3
    this.query = this.query.skip(skip).limit(limit);

    return this;
  }
}

module.exports = APIFeature;
